"""Integration of the VCDB and EuRepoC incident sources into a unified schema.

NVD is not merged here on purpose; vulnerabilities and incidents have
different units of analysis, so NVD produces its own enriched dataset
(see src/preprocessing/enrichment.py and src/preprocessing/run.py).
"""

from __future__ import annotations

import logging

import pandas as pd

from src.preprocessing import cleaning
from src.preprocessing.countries import add_country_codes
from src.preprocessing.taxonomies import (
    ATTACK_UNKNOWN,
    EUREPOC_CATEGORY_TO_SECTOR,
    EUREPOC_TYPE_PRECEDENCE,
    VCDB_ACTION_PRECEDENCE,
    VCDB_NAICS_TO_SECTOR,
)
from src.utils import config

logger = logging.getLogger(__name__)

INCIDENT_COLUMNS = [
    "source",
    "incident_id",
    "date",
    "year",
    "month",
    "country_iso2",
    "country_name",
    "country_numeric",
    "sector",
    "attack_category",
    "incident_type_raw",
    "actor_raw",
    "weighted_intensity",
    "title",
]

_TITLE_MAX_CHARS = 200


def prepare_vcdb_incidents(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Transforms flattened VCDB records into the unified incident schema.

    Args:
        raw_df: DataFrame produced by the VCDB acquisition client.

    Returns:
        A DataFrame with the unified incident columns.
    """
    df = cleaning.filter_date_range(
        raw_df, "year", config.ANALYSIS_START_YEAR, config.ANALYSIS_END_YEAR
    )
    df["month"] = pd.to_numeric(df["month"], errors="coerce").fillna(1).astype(int).clip(1, 12)
    df["year"] = df["year"].astype(int)
    df["date"] = pd.to_datetime({"year": df["year"], "month": df["month"], "day": 1})
    df["sector"] = df["victim_industry"].astype(str).str[:2]
    df = cleaning.normalize_sector_names(df, "sector", VCDB_NAICS_TO_SECTOR)
    df["attack_category"] = df["action_types"].map(_vcdb_attack_category)
    df["country"] = df["victim_country"].replace("Unknown", None)
    df = add_country_codes(df, "country", is_alpha_2=True)
    df["source"] = "VCDB"
    df["incident_type_raw"] = df["action_types"]
    df["actor_raw"] = df["actor_types"]
    df["weighted_intensity"] = pd.NA
    df["title"] = df["summary"].astype(str).str[:_TITLE_MAX_CHARS]
    logger.info("VCDB incidents prepared: %d rows", len(df))
    return df[INCIDENT_COLUMNS]


def prepare_eurepoc_incidents(raw_df: pd.DataFrame) -> pd.DataFrame:
    """Transforms the EuRepoC global dataset into the unified incident schema.

    Multi-valued fields (';'-separated) keep their first value, which
    EuRepoC documents as the main receiver.

    Args:
        raw_df: EuRepoC global dataset as downloaded.

    Returns:
        A DataFrame with the unified incident columns.
    """
    df = cleaning.normalize_dates(raw_df, "start_date", dayfirst=True)
    df = cleaning.filter_date_range(
        df, "start_date", config.ANALYSIS_START_YEAR, config.ANALYSIS_END_YEAR
    )
    df["date"] = df["start_date"]
    df["year"] = df["date"].dt.year.astype(int)
    df["month"] = df["date"].dt.month.astype(int)
    df["sector"] = df["receiver_category"].map(_first_value).map(_normalize_corporate_label)
    df = cleaning.normalize_sector_names(df, "sector", EUREPOC_CATEGORY_TO_SECTOR)
    df["attack_category"] = df["incident_type"].map(_eurepoc_attack_category)
    df["country"] = df["receiver_country"].map(_first_value)
    df = add_country_codes(df, "country", is_alpha_2=False)
    df["source"] = "EuRepoC"
    df["incident_id"] = df["incident_id"].astype(str)
    df["incident_type_raw"] = df["incident_type"]
    df["actor_raw"] = df["initiator_category"].map(_first_value)
    df["title"] = df["name"].astype(str).str[:_TITLE_MAX_CHARS]
    logger.info("EuRepoC incidents prepared: %d rows", len(df))
    return df[INCIDENT_COLUMNS]


def merge_sources(vcdb_df: pd.DataFrame, eurepoc_df: pd.DataFrame) -> pd.DataFrame:
    """Merges the prepared incident sources into a single DataFrame.

    Args:
        vcdb_df: Output of prepare_vcdb_incidents.
        eurepoc_df: Output of prepare_eurepoc_incidents.

    Returns:
        A unified DataFrame with a shared schema across sources, including
        a source identifier column.
    """
    merged = pd.concat([vcdb_df, eurepoc_df], ignore_index=True)
    merged["incident_id"] = merged["incident_id"].astype(str)
    logger.info(
        "Unified incidents: %d rows (%s)",
        len(merged),
        ", ".join(f"{s}={n}" for s, n in merged["source"].value_counts().items()),
    )
    return merged


def _first_value(value: object) -> str | None:
    """Returns the first entry of a ';'-separated multi-value field."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    return str(value).split(";")[0].strip()


def _normalize_corporate_label(value: str | None) -> str | None:
    """Collapses the verbose 'Corporate Targets (…)' label to its prefix."""
    if value is not None and value.startswith("Corporate Targets"):
        return "Corporate Targets"
    return value


def _vcdb_attack_category(action_types: object) -> str:
    """Resolves the primary attack category from VERIS first-level actions."""
    if action_types is None or (isinstance(action_types, float) and pd.isna(action_types)):
        return ATTACK_UNKNOWN
    actions = set(str(action_types).split(";"))
    for action, category in VCDB_ACTION_PRECEDENCE:
        if action in actions:
            return category
    return ATTACK_UNKNOWN


def _eurepoc_attack_category(incident_type: object) -> str:
    """Resolves the primary attack category from the EuRepoC incident type."""
    if incident_type is None or (isinstance(incident_type, float) and pd.isna(incident_type)):
        return ATTACK_UNKNOWN
    text = str(incident_type)
    for token, category in EUREPOC_TYPE_PRECEDENCE:
        if token in text:
            return category
    return ATTACK_UNKNOWN
