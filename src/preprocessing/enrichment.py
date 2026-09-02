"""Enrichment of the NVD dataset with KEV exploitation flags and EPSS scores."""

from __future__ import annotations

import logging

import pandas as pd

logger = logging.getLogger(__name__)


def add_kev_flags(nvd_df: pd.DataFrame, kev_catalog: dict) -> pd.DataFrame:
    """Adds known-exploitation flags from the CISA KEV catalog.

    Args:
        nvd_df: NVD vulnerability DataFrame with a cve_id column.
        kev_catalog: Parsed KEV catalog JSON.

    Returns:
        A copy of nvd_df with is_kev, kev_date_added, and kev_ransomware.
    """
    entries = kev_catalog.get("vulnerabilities", [])
    kev_df = pd.DataFrame(
        {
            "cve_id": [entry.get("cveID") for entry in entries],
            "kev_date_added": [entry.get("dateAdded") for entry in entries],
            "kev_ransomware": [
                str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
                for entry in entries
            ],
        }
    ).drop_duplicates(subset="cve_id")
    result = nvd_df.merge(kev_df, on="cve_id", how="left")
    result["is_kev"] = result["kev_date_added"].notna()
    result["kev_ransomware"] = result["kev_ransomware"].fillna(False).astype(bool)
    result["kev_date_added"] = pd.to_datetime(result["kev_date_added"], errors="coerce")
    logger.info("KEV flags added: %d CVEs marked as exploited", int(result["is_kev"].sum()))
    return result


def add_epss_scores(nvd_df: pd.DataFrame, epss_df: pd.DataFrame) -> pd.DataFrame:
    """Adds EPSS exploitation probability scores.

    Args:
        nvd_df: NVD vulnerability DataFrame with a cve_id column.
        epss_df: EPSS snapshot with cve, epss, and percentile columns.

    Returns:
        A copy of nvd_df with epss_score and epss_percentile.
    """
    scores = epss_df.rename(
        columns={"cve": "cve_id", "epss": "epss_score", "percentile": "epss_percentile"}
    ).drop_duplicates(subset="cve_id")
    result = nvd_df.merge(
        scores[["cve_id", "epss_score", "epss_percentile"]], on="cve_id", how="left"
    )
    coverage = result["epss_score"].notna().mean() * 100
    logger.info("EPSS scores added with %.1f%% coverage", coverage)
    return result
