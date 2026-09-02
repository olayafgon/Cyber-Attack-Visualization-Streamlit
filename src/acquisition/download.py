"""Command-line orchestrator for downloading every raw data source.

Usage:
    python -m src.acquisition.download --source all
    python -m src.acquisition.download --source nvd --start-year 2015 --end-year 2025
    python -m src.acquisition.download --source kev --dry-run
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import pathlib
import sys

import pandas as pd
import requests

from src.acquisition import (
    epss_client,
    eurepoc_client,
    hibp_client,
    kev_client,
    nvd_client,
    ransomwhere_client,
    vcdb_client,
)
from src.acquisition.http_utils import check_url, default_headers
from src.utils import config
from src.utils.io import write_dataset

logger = logging.getLogger(__name__)

OPTIONAL_SOURCES = {"ransomwhere"}
_SOURCE_ORDER = ("kev", "epss", "hibp", "ransomwhere", "eurepoc", "vcdb", "nvd")


# One runner per source, sharing a signature so _RUNNERS can dispatch on the
# source name alone; only NVD reads anything out of the parsed arguments.
def _run_kev(args: argparse.Namespace) -> dict:
    destination = config.DATA_RAW_DIR / "kev" / "kev_catalog.json"
    path = kev_client.download(destination)
    catalog = json.loads(path.read_text(encoding="utf-8"))
    return _manifest("kev", [kev_client.KEV_CATALOG_URL], [path], len(catalog.get("vulnerabilities", [])))


def _run_epss(args: argparse.Namespace) -> dict:
    destination = config.DATA_RAW_DIR / "epss" / "epss_scores-current.csv.gz"
    path = epss_client.download(destination)
    records = len(pd.read_csv(path, comment="#"))
    return _manifest("epss", [epss_client.EPSS_SNAPSHOT_URL], [path], records)


def _run_hibp(args: argparse.Namespace) -> dict:
    destination = config.DATA_RAW_DIR / "hibp" / "breaches.json"
    path = hibp_client.download(destination)
    breaches = json.loads(path.read_text(encoding="utf-8"))
    return _manifest("hibp", [hibp_client.HIBP_BREACHES_URL], [path], len(breaches))


def _run_ransomwhere(args: argparse.Namespace) -> dict:
    destination = config.DATA_RAW_DIR / "ransomwhere" / "payments.json"
    path = ransomwhere_client.download(destination)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payments = payload.get("result", payload) if isinstance(payload, dict) else payload
    return _manifest("ransomwhere", [ransomwhere_client.RANSOMWHERE_EXPORT_URL], [path], len(payments))


def _run_eurepoc(args: argparse.Namespace) -> dict:
    destination = config.DATA_RAW_DIR / "eurepoc"
    paths = eurepoc_client.download_datasets(destination)
    records = len(eurepoc_client.load_incidents(destination))
    urls = [
        f"{eurepoc_client.ZENODO_FILES_URL}/{name}/content"
        for name in eurepoc_client.DATASET_FILENAMES
    ]
    return _manifest("eurepoc", urls, paths, records)


def _run_vcdb(args: argparse.Namespace) -> dict:
    archive_path = config.DATA_RAW_DIR / "vcdb" / "vcdb-master.zip"
    vcdb_client.download_repository(archive_path)
    incidents = vcdb_client.load_incidents(archive_path)
    parquet_path = config.DATA_RAW_DIR / "vcdb" / "vcdb_incidents.parquet"
    write_dataset(incidents, parquet_path)
    return _manifest("vcdb", [vcdb_client.VCDB_ARCHIVE_URL], [archive_path, parquet_path], len(incidents))


def _run_nvd(args: argparse.Namespace) -> dict:
    start_date = f"{args.start_year}-01-01"
    end_date = f"{args.end_year}-12-31"
    df = nvd_client.fetch_cves(start_date, end_date)
    destination = config.DATA_RAW_DIR / "nvd" / "nvd_cves.parquet"
    nvd_client.save_raw(df, destination)
    return _manifest("nvd", [nvd_client.NVD_API_URL], [destination], len(df))


_RUNNERS = {
    "kev": _run_kev,
    "epss": _run_epss,
    "hibp": _run_hibp,
    "ransomwhere": _run_ransomwhere,
    "eurepoc": _run_eurepoc,
    "vcdb": _run_vcdb,
    "nvd": _run_nvd,
}


def _manifest(source: str, urls: list[str], files: list[pathlib.Path], records: int) -> dict:
    """Builds and persists the download manifest for one source."""
    manifest = {
        "source": source,
        "urls": urls,
        "downloaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "records": records,
        "files": [
            {
                "path": str(path.relative_to(config.PROJECT_ROOT)),
                "size_bytes": path.stat().st_size,
            }
            for path in files
        ],
    }
    manifest_path = config.DATA_RAW_DIR / source / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Manifest written to %s (%d records)", manifest_path, records)
    return manifest


def _dry_run(source: str, args: argparse.Namespace) -> None:
    """Probes the source endpoints without persisting anything."""
    if source == "nvd":
        params = {
            "pubStartDate": f"{args.start_year}-01-01T00:00:00.000+00:00",
            "pubEndDate": f"{args.start_year}-01-31T23:59:59.999+00:00",
            "resultsPerPage": 1,
        }
        response = requests.get(
            nvd_client.NVD_API_URL, params=params, headers=default_headers(), timeout=60
        )
        response.raise_for_status()
        total = response.json().get("totalResults")
        logger.info("[nvd] HTTP %d, totalResults=%s for January %d", response.status_code, total, args.start_year)
        return
    probe_urls = {
        "kev": [kev_client.KEV_CATALOG_URL],
        "epss": [epss_client.EPSS_SNAPSHOT_URL],
        "hibp": [hibp_client.HIBP_BREACHES_URL],
        "ransomwhere": [ransomwhere_client.RANSOMWHERE_EXPORT_URL],
        "eurepoc": [
            f"{eurepoc_client.ZENODO_FILES_URL}/{eurepoc_client.GLOBAL_DATASET_FILENAME}/content"
        ],
        "vcdb": [vcdb_client.VCDB_ARCHIVE_URL],
    }
    for url in probe_urls[source]:
        status = check_url(url)
        logger.info("[%s] HTTP %d for %s", source, status, url)


def main(argv: list[str] | None = None) -> int:
    """Entry point for the acquisition CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m src.acquisition.download",
        description="Download the raw datasets used by the case study.",
    )
    parser.add_argument(
        "--source",
        required=True,
        choices=(*_SOURCE_ORDER, "all"),
        help="Data source to download, or 'all' for every source (NVD last).",
    )
    parser.add_argument("--start-year", type=int, default=config.ANALYSIS_START_YEAR)
    parser.add_argument("--end-year", type=int, default=config.ANALYSIS_END_YEAR)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Probe the source endpoints without downloading or persisting data.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sources = list(_SOURCE_ORDER) if args.source == "all" else [args.source]
    failures: list[str] = []
    for source in sources:
        try:
            if args.dry_run:
                _dry_run(source, args)
            else:
                _RUNNERS[source](args)
        except Exception:
            logger.exception("Source '%s' failed", source)
            if source not in OPTIONAL_SOURCES:
                failures.append(source)
            else:
                logger.warning("Source '%s' is optional; continuing", source)
    if failures:
        logger.error("Failed sources: %s", ", ".join(failures))
        return 1
    logger.info("Done: %s", ", ".join(sources))
    return 0


if __name__ == "__main__":
    sys.exit(main())
