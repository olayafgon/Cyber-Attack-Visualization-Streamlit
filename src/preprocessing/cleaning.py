"""Cleaning routines applied independently to each raw data source."""

from __future__ import annotations

import pandas as pd

from src.preprocessing.taxonomies import SECTOR_UNKNOWN, SEVERITY_BINS


def normalize_dates(df: pd.DataFrame, date_column: str, dayfirst: bool = False) -> pd.DataFrame:
    """Converts a date column to datetime64, coercing invalid values to NaT.

    Args:
        df: Input DataFrame.
        date_column: Name of the column holding date values.
        dayfirst: Whether the source uses day-first formats (dd.mm.yyyy).

    Returns:
        A copy of df with date_column parsed as timezone-naive datetimes.
    """
    result = df.copy()
    parsed = pd.to_datetime(
        result[date_column], errors="coerce", dayfirst=dayfirst, format="mixed"
    )
    if parsed.dt.tz is not None:
        parsed = parsed.dt.tz_localize(None)
    result[date_column] = parsed
    return result


def impute_missing_cvss(df: pd.DataFrame, group_column: str, cvss_column: str) -> pd.DataFrame:
    """Imputes missing CVSS scores using the mean score within each CWE category.

    Records whose group has no observed score fall back to the global mean.
    A boolean column '<cvss_column>_imputed' marks the affected rows.

    Args:
        df: Input DataFrame containing CVSS scores.
        group_column: Column used to group records (typically the CWE identifier).
        cvss_column: Column holding the CVSS score to impute.

    Returns:
        A copy of df with missing values in cvss_column filled.
    """
    result = df.copy()
    result[f"{cvss_column}_imputed"] = result[cvss_column].isna()
    group_means = result.groupby(group_column)[cvss_column].transform("mean")
    result[cvss_column] = result[cvss_column].fillna(group_means)
    result[cvss_column] = result[cvss_column].fillna(result[cvss_column].mean())
    result[cvss_column] = result[cvss_column].round(1)
    return result


def filter_date_range(df: pd.DataFrame, date_column: str, start_year: int, end_year: int) -> pd.DataFrame:
    """Filters records to those within an inclusive year range.

    Args:
        df: Input DataFrame.
        date_column: Column holding datetime values or numeric years.
        start_year: First year to include.
        end_year: Last year to include.

    Returns:
        A filtered copy of df.
    """
    column = df[date_column]
    if pd.api.types.is_numeric_dtype(column):
        years = column
    else:
        years = pd.to_datetime(column, errors="coerce").dt.year
    return df[years.between(start_year, end_year)].copy()


def normalize_sector_names(df: pd.DataFrame, sector_column: str, mapping: dict[str, str]) -> pd.DataFrame:
    """Normalizes sector names to a shared taxonomy across sources.

    Labels absent from the mapping fall back to the shared unknown bucket.

    Args:
        df: Input DataFrame.
        sector_column: Column holding the sector label.
        mapping: Mapping from source-specific labels to the shared taxonomy.

    Returns:
        A copy of df with sector_column normalized.
    """
    result = df.copy()
    result[sector_column] = result[sector_column].map(mapping).fillna(SECTOR_UNKNOWN)
    return result


def derive_severity_from_score(df: pd.DataFrame, score_column: str, severity_column: str) -> pd.DataFrame:
    """Derives a uniform severity band from the CVSS score.

    Applies the CVSS v3 thresholds to every record so that v2-only scores
    share the same ordinal scale (LOW, MEDIUM, HIGH, CRITICAL).

    Args:
        df: Input DataFrame.
        score_column: Column holding the numeric CVSS score.
        severity_column: Output column for the severity label.

    Returns:
        A copy of df with severity_column populated.
    """
    result = df.copy()
    bins = [SEVERITY_BINS[0][0] - 0.1] + [upper for _, upper, _ in SEVERITY_BINS]
    labels = [label for _, _, label in SEVERITY_BINS]
    result[severity_column] = pd.cut(result[score_column], bins=bins, labels=labels).astype("object")
    return result
