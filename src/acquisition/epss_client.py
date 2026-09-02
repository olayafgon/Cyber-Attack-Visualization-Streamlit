"""Client for the FIRST.org Exploit Prediction Scoring System (EPSS) feed."""

from __future__ import annotations

import pathlib

from src.acquisition.http_utils import download_file

EPSS_SNAPSHOT_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def download(destination: pathlib.Path) -> pathlib.Path:
    """Downloads the current EPSS scores snapshot.

    The file is a gzip-compressed CSV whose first line is a comment with
    the model version and score date; read it with comment="#".

    Args:
        destination: Target file path for the snapshot.

    Returns:
        The path to the downloaded snapshot.
    """
    return download_file(EPSS_SNAPSHOT_URL, destination)
