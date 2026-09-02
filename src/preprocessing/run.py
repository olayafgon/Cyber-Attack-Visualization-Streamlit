"""Preprocessing pipeline turning the raw layer into analysis-ready datasets.

Usage:
    python -m src.preprocessing.run
"""

from __future__ import annotations

import datetime
import json
import logging
import sys

import pandas as pd

from src.preprocessing import cleaning, enrichment, integration
from src.preprocessing.countries import build_country_table
from src.preprocessing.taxonomies import (
    CWE_UNKNOWN,
    HIBP_KEYWORDS_TO_SECTOR,
    SECTOR_EDUCATION,
    SECTOR_PUBLIC,
    SECTOR_UNKNOWN,
)
from src.utils import config
from src.utils.io import write_dataset

logger = logging.getLogger(__name__)

VULNERABILITY_COLUMNS = [
    "cve_id",
    "published",
    "year",
    "month",
    "cvss_score",
    "cvss_imputed",
    "cvss_severity",
    "cvss_version",
    "attack_vector",
    "cwe_id",
    "cpe_count",
    "is_kev",
    "kev_date_added",
    "kev_ransomware",
    "epss_score",
    "epss_percentile",
]


def process_vulnerabilities() -> pd.DataFrame:
    """Builds the enriched vulnerability dataset from NVD, KEV, and EPSS."""
    df = pd.read_parquet(config.DATA_RAW_DIR / "nvd" / "nvd_cves.parquet")
    initial = len(df)
    df = df[df["vuln_status"] != "Rejected"]
    logger.info("NVD: %d records after excluding %d Rejected", len(df), initial - len(df))

    df = cleaning.normalize_dates(df, "published")
    df = cleaning.filter_date_range(
        df, "published", config.ANALYSIS_START_YEAR, config.ANALYSIS_END_YEAR
    )
    df["year"] = df["published"].dt.year.astype(int)
    df["month"] = df["published"].dt.month.astype(int)

    df["cwe_id"] = df["cwe_id"].where(
        df["cwe_id"].astype(str).str.startswith("CWE-"), CWE_UNKNOWN
    )
    df = cleaning.impute_missing_cvss(df, "cwe_id", "cvss_score")
    df = df.rename(columns={"cvss_score_imputed": "cvss_imputed"})
    df = cleaning.derive_severity_from_score(df, "cvss_score", "cvss_severity")

    kev_catalog = json.loads(
        (config.DATA_RAW_DIR / "kev" / "kev_catalog.json").read_text(encoding="utf-8")
    )
    df = enrichment.add_kev_flags(df, kev_catalog)
    epss = pd.read_csv(config.DATA_RAW_DIR / "epss" / "epss_scores-current.csv.gz", comment="#")
    df = enrichment.add_epss_scores(df, epss)

    df = df[VULNERABILITY_COLUMNS]
    write_dataset(df, config.DATA_PROCESSED_DIR / "vulnerabilities.parquet")
    logger.info("vulnerabilities.parquet written: %d rows", len(df))
    return df


def aggregate_vulnerabilities_monthly(df: pd.DataFrame) -> None:
    """Builds the year-month aggregate consumed by the dashboard."""
    monthly = (
        df.groupby(["year", "month", "cvss_severity", "is_kev"], observed=True)
        .agg(cve_count=("cve_id", "count"), epss_mean=("epss_score", "mean"))
        .reset_index()
    )
    write_dataset(monthly, config.DATA_PROCESSED_DIR / "vulnerabilities_monthly.parquet")
    logger.info("vulnerabilities_monthly.parquet written: %d rows", len(monthly))


def process_incidents() -> None:
    """Builds the unified incident dataset from VCDB and EuRepoC."""
    vcdb_raw = pd.read_parquet(config.DATA_RAW_DIR / "vcdb" / "vcdb_incidents.parquet")
    eurepoc_raw = pd.read_csv(
        config.DATA_RAW_DIR / "eurepoc" / "eurepoc_global_dataset_1_3.csv", low_memory=False
    )
    merged = integration.merge_sources(
        integration.prepare_vcdb_incidents(vcdb_raw),
        integration.prepare_eurepoc_incidents(eurepoc_raw),
    )
    write_dataset(merged, config.DATA_PROCESSED_DIR / "incidents.parquet")
    logger.info("incidents.parquet written: %d rows", len(merged))


def process_breaches() -> None:
    """Builds the cleaned HIBP breach dataset with a derived sector."""
    breaches = json.loads(
        (config.DATA_RAW_DIR / "hibp" / "breaches.json").read_text(encoding="utf-8")
    )
    df = pd.DataFrame(breaches)
    initial = len(df)
    genuine = ~(df["IsFabricated"] | df["IsSpamList"] | df["IsStealerLog"] | df["IsRetired"])
    df = df[genuine]
    logger.info("HIBP: %d breaches after excluding %d non-genuine", len(df), initial - len(df))

    df = cleaning.normalize_dates(df, "BreachDate")
    df = cleaning.filter_date_range(
        df, "BreachDate", config.ANALYSIS_START_YEAR, config.ANALYSIS_END_YEAR
    )
    df["sector"] = df.apply(
        lambda row: _infer_hibp_sector(row["Title"], row["Domain"], row["Description"]), axis=1
    )
    result = pd.DataFrame(
        {
            "name": df["Name"],
            "title": df["Title"],
            "domain": df["Domain"],
            "date": df["BreachDate"],
            "year": df["BreachDate"].dt.year.astype(int),
            "pwn_count": df["PwnCount"],
            "sector": df["sector"],
            "is_verified": df["IsVerified"],
            "is_sensitive": df["IsSensitive"],
            "data_classes": df["DataClasses"].map(lambda values: ";".join(values)),
        }
    )
    write_dataset(result, config.DATA_PROCESSED_DIR / "breaches.parquet")
    logger.info("breaches.parquet written: %d rows", len(result))


def process_ransomware_payments() -> None:
    """Flattens Ransomwhere addresses into one verified payment per row."""
    payload = json.loads(
        (config.DATA_RAW_DIR / "ransomwhere" / "payments.json").read_text(encoding="utf-8")
    )
    addresses = payload.get("result", payload) if isinstance(payload, dict) else payload
    rows = []
    for entry in addresses:
        for transaction in entry.get("transactions", []):
            timestamp = transaction.get("time")
            if not timestamp:
                continue
            rows.append(
                {
                    "date": datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc),
                    "family": entry.get("family"),
                    "blockchain": entry.get("blockchain"),
                    "amount_usd": transaction.get("amountUSD"),
                }
            )
    df = pd.DataFrame(rows)
    df["date"] = df["date"].dt.tz_localize(None)
    df["year"] = df["date"].dt.year
    df = cleaning.filter_date_range(
        df, "year", config.ANALYSIS_START_YEAR, config.ANALYSIS_END_YEAR
    )
    write_dataset(df, config.DATA_PROCESSED_DIR / "ransomware_payments.parquet")
    logger.info("ransomware_payments.parquet written: %d rows", len(df))


def _infer_hibp_sector(title: object, domain: object, description: object) -> str:
    """Infers the breach sector from title, domain, and description keywords."""
    domain_text = str(domain or "").lower()
    if domain_text.endswith(".gov") or ".gov." in domain_text:
        return SECTOR_PUBLIC
    if domain_text.endswith(".edu") or ".edu." in domain_text:
        return SECTOR_EDUCATION
    text = f"{title or ''} {domain_text} {description or ''}".lower()
    for keywords, sector in HIBP_KEYWORDS_TO_SECTOR:
        if any(keyword in text for keyword in keywords):
            return sector
    return SECTOR_UNKNOWN


def main() -> int:
    """Runs the full preprocessing pipeline."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    vulnerabilities = process_vulnerabilities()
    aggregate_vulnerabilities_monthly(vulnerabilities)
    process_incidents()
    process_breaches()
    process_ransomware_payments()
    build_country_table(config.DATA_EXTERNAL_DIR / "country_codes.csv")
    logger.info("Preprocessing pipeline completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
