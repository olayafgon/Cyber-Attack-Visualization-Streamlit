"""Loader for the Verizon Community Database (VCDB) JSON dataset."""

from __future__ import annotations

import json
import logging
import pathlib
import zipfile
from collections.abc import Iterator

import pandas as pd

from src.acquisition.http_utils import download_file

VCDB_ARCHIVE_URL = "https://github.com/vz-risk/VCDB/archive/refs/heads/master.zip"
_VALIDATED_JSON_DIR = "data/json/validated/"

logger = logging.getLogger(__name__)


def download_repository(destination: pathlib.Path) -> pathlib.Path:
    """Downloads the VCDB repository archive from GitHub.

    The archive is kept compressed; incident files are read directly from
    the zip to avoid extracting thousands of small files.

    Args:
        destination: Target path for the zip archive.

    Returns:
        The path to the downloaded archive.
    """
    return download_file(VCDB_ARCHIVE_URL, destination)


def load_incidents(source_path: pathlib.Path) -> pd.DataFrame:
    """Loads VCDB incident records from a local JSON export.

    Args:
        source_path: Path to the repository zip archive, a directory of
            VERIS JSON files, or a single JSON file.

    Returns:
        A DataFrame with one row per incident, including attack type,
        sector, attack vector, country, and year.
    """
    if source_path.suffix == ".zip":
        records = list(_iter_zip_incidents(source_path))
    elif source_path.is_dir():
        records = [
            _parse_incident(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted(source_path.glob("*.json"))
        ]
    else:
        records = [_parse_incident(json.loads(source_path.read_text(encoding="utf-8")))]
    logger.info("Parsed %d VCDB incidents from %s", len(records), source_path)
    return pd.DataFrame(records)


def _iter_zip_incidents(archive_path: pathlib.Path) -> Iterator[dict]:
    """Yields parsed incidents from the validated JSON files inside the zip."""
    with zipfile.ZipFile(archive_path) as archive:
        names = [
            name
            for name in archive.namelist()
            if _VALIDATED_JSON_DIR in name and name.endswith(".json")
        ]
        logger.info("Reading %d incident files from %s", len(names), archive_path.name)
        for name in sorted(names):
            with archive.open(name) as handle:
                yield _parse_incident(json.load(handle))


def _parse_incident(record: dict) -> dict:
    """Flattens one VERIS incident record into a plain row."""
    victim = record.get("victim", {})
    timeline_incident = record.get("timeline", {}).get("incident", {})
    attributes = record.get("attribute", {})
    countries = victim.get("country", [])
    return {
        "incident_id": record.get("incident_id"),
        "source_id": record.get("source_id"),
        "year": timeline_incident.get("year"),
        "month": timeline_incident.get("month"),
        "action_types": ";".join(sorted(record.get("action", {}).keys())) or None,
        "actor_types": ";".join(sorted(record.get("actor", {}).keys())) or None,
        "security_incident": record.get("security_incident"),
        "victim_industry": victim.get("industry"),
        "victim_country": countries[0] if countries else None,
        "victim_employee_count": victim.get("employee_count"),
        "affects_confidentiality": "confidentiality" in attributes,
        "affects_integrity": "integrity" in attributes,
        "affects_availability": "availability" in attributes,
        "data_total": attributes.get("confidentiality", {}).get("data_total"),
        "summary": record.get("summary"),
    }
