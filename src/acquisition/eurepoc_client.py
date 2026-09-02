"""Loader for the European Repository of Cyber Incidents (EuRepoC) dataset."""

from __future__ import annotations

import logging
import pathlib

import pandas as pd

from src.acquisition.http_utils import download_file
from src.utils.io import read_dataset

ZENODO_RECORD_ID = "14965395"
ZENODO_FILES_URL = f"https://zenodo.org/api/records/{ZENODO_RECORD_ID}/files"

GLOBAL_DATASET_FILENAME = "eurepoc_global_dataset_1_3.csv"
DATASET_FILENAMES = (
    GLOBAL_DATASET_FILENAME,
    "eurepoc_receiver_dataset_1.3.csv",
    "eurepoc_attribution_dataset_1.3.csv",
    "eurepoc_dyadic_dataset_0_1.csv",
    "eurepoc_codebook_1_2.pdf",
)

logger = logging.getLogger(__name__)


def download_datasets(destination: pathlib.Path) -> list[pathlib.Path]:
    """Downloads the EuRepoC datasets and codebook from Zenodo.

    Args:
        destination: Directory where the files are stored.

    Returns:
        The list of downloaded file paths.
    """
    paths = []
    for filename in DATASET_FILENAMES:
        url = f"{ZENODO_FILES_URL}/{filename}/content"
        paths.append(download_file(url, destination / filename))
    return paths


def load_incidents(source_path: pathlib.Path) -> pd.DataFrame:
    """Loads EuRepoC incident records from a local export.

    Args:
        source_path: Path to the EuRepoC CSV or JSON export, or to the
            directory containing the global dataset.

    Returns:
        A DataFrame with one row per incident, including attacker
        attribution, country, sector, and incident timestamp.
    """
    if source_path.is_dir():
        source_path = source_path / GLOBAL_DATASET_FILENAME
    df = read_dataset(source_path)
    logger.info("Loaded %d EuRepoC incidents from %s", len(df), source_path.name)
    return df
