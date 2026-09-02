"""Client for the National Vulnerability Database (NVD) REST API v2."""

from __future__ import annotations

import datetime
import logging
import pathlib
import time

import pandas as pd
import requests

from src.acquisition.http_utils import default_headers
from src.utils import config
from src.utils.io import write_dataset

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

WINDOW_DAYS = 120
REQUEST_DELAY_SECONDS = 6.0
REQUEST_TIMEOUT_SECONDS = 120
MAX_RETRIES = 5
RETRY_BASE_DELAY_SECONDS = 30.0
_RETRYABLE_STATUS_CODES = (403, 429, 500, 502, 503)

logger = logging.getLogger(__name__)


def fetch_cves(
    start_date: str,
    end_date: str,
    results_per_page: int = 2000,
    windows_dir: pathlib.Path | None = None,
) -> pd.DataFrame:
    """Fetches CVE records published within a date range.

    The range is split into windows of at most 120 days (NVD API limit).
    Each completed window is persisted to windows_dir so an interrupted
    download can resume by skipping windows already on disk.

    Args:
        start_date: Inclusive start date in ISO 8601 format (YYYY-MM-DD).
        end_date: Inclusive end date in ISO 8601 format (YYYY-MM-DD).
        results_per_page: Number of records requested per API page.
        windows_dir: Directory for per-window checkpoint files. Defaults to
            data/raw/nvd/windows.

    Returns:
        A DataFrame with one row per CVE, including CVSS score, severity,
        CWE identifier, and affected products.
    """
    if windows_dir is None:
        windows_dir = config.DATA_RAW_DIR / "nvd" / "windows"
    windows_dir.mkdir(parents=True, exist_ok=True)

    windows = _split_into_windows(
        datetime.date.fromisoformat(start_date), datetime.date.fromisoformat(end_date)
    )
    frames: list[pd.DataFrame] = []
    for index, (window_start, window_end) in enumerate(windows, start=1):
        window_path = windows_dir / f"nvd_{window_start}_{window_end}.parquet"
        if window_path.exists():
            frame = pd.read_parquet(window_path)
            logger.info(
                "[%d/%d] Window %s..%s already downloaded (%d records), skipping",
                index, len(windows), window_start, window_end, len(frame),
            )
        else:
            logger.info("[%d/%d] Fetching window %s..%s", index, len(windows), window_start, window_end)
            records = _fetch_window(window_start, window_end, results_per_page)
            frame = pd.DataFrame(records, columns=_RECORD_COLUMNS)
            write_dataset(frame, window_path)
            logger.info(
                "[%d/%d] Window %s..%s completed with %d records",
                index, len(windows), window_start, window_end, len(frame),
            )
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


def save_raw(df: pd.DataFrame, destination: pathlib.Path) -> None:
    """Persists the raw NVD dataset to disk.

    Args:
        df: DataFrame returned by fetch_cves.
        destination: Target file path.
    """
    write_dataset(df, destination)
    logger.info("Consolidated NVD dataset saved to %s (%d records)", destination, len(df))


def _split_into_windows(
    start: datetime.date, end: datetime.date
) -> list[tuple[datetime.date, datetime.date]]:
    """Splits an inclusive date range into consecutive windows of WINDOW_DAYS."""
    windows = []
    window_start = start
    while window_start <= end:
        window_end = min(window_start + datetime.timedelta(days=WINDOW_DAYS - 1), end)
        windows.append((window_start, window_end))
        window_start = window_end + datetime.timedelta(days=1)
    return windows


def _fetch_window(
    window_start: datetime.date, window_end: datetime.date, results_per_page: int
) -> list[dict]:
    """Fetches and parses every CVE published inside one window."""
    records: list[dict] = []
    start_index = 0
    total_results: int | None = None
    while total_results is None or start_index < total_results:
        params = {
            "pubStartDate": f"{window_start}T00:00:00.000+00:00",
            "pubEndDate": f"{window_end}T23:59:59.999+00:00",
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        payload = _get_with_retries(params)
        total_results = payload.get("totalResults", 0)
        for item in payload.get("vulnerabilities", []):
            records.append(_parse_vulnerability(item))
        start_index += results_per_page
        logger.info(
            "  page done: %d/%d records in window", min(start_index, total_results), total_results
        )
        if start_index < total_results:
            time.sleep(REQUEST_DELAY_SECONDS)
    return records


def _get_with_retries(params: dict) -> dict:
    """Performs a GET against the NVD API with exponential backoff."""
    last_error: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=default_headers(),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code in _RETRYABLE_STATUS_CODES:
                raise requests.HTTPError(f"HTTP {response.status_code}", response=response)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as error:
            last_error = error
            delay = RETRY_BASE_DELAY_SECONDS * (2**attempt)
            logger.warning(
                "NVD request failed (%s); retry %d/%d in %.0f s",
                error, attempt + 1, MAX_RETRIES, delay,
            )
            time.sleep(delay)
    raise RuntimeError(f"NVD request failed after {MAX_RETRIES} retries") from last_error


_RECORD_COLUMNS = [
    "cve_id",
    "published",
    "last_modified",
    "vuln_status",
    "cvss_score",
    "cvss_severity",
    "cvss_version",
    "attack_vector",
    "cwe_id",
    "cpe_count",
    "description_en",
]

_CVSS_METRIC_KEYS = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _parse_vulnerability(item: dict) -> dict:
    """Flattens one NVD vulnerability entry into a plain record."""
    cve = item.get("cve", {})
    score, severity, version, attack_vector = _extract_cvss(cve.get("metrics", {}))
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_version": version,
        "attack_vector": attack_vector,
        "cwe_id": _extract_primary_cwe(cve.get("weaknesses", [])),
        "cpe_count": _count_cpe_matches(cve.get("configurations", [])),
        "description_en": _extract_english_description(cve.get("descriptions", [])),
    }


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None, str | None]:
    """Extracts score, severity, version, and attack vector, preferring v3.1."""
    for metric_key, version in _CVSS_METRIC_KEYS:
        entries = metrics.get(metric_key)
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss_data = entry.get("cvssData", {})
        severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
        attack_vector = cvss_data.get("attackVector") or cvss_data.get("accessVector")
        return cvss_data.get("baseScore"), severity, version, attack_vector
    return None, None, None, None


def _extract_primary_cwe(weaknesses: list[dict]) -> str | None:
    """Returns the first CWE identifier, preferring Primary-typed weaknesses."""
    ordered = sorted(weaknesses, key=lambda w: w.get("type") != "Primary")
    for weakness in ordered:
        for description in weakness.get("description", []):
            value = description.get("value", "")
            if value.startswith("CWE-"):
                return value
    return None


def _count_cpe_matches(configurations: list[dict]) -> int:
    """Counts CPE match entries across all configuration nodes."""
    count = 0
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            count += len(node.get("cpeMatch", []))
    return count


def _extract_english_description(descriptions: list[dict]) -> str | None:
    """Returns the English description text when present."""
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value")
    return None
