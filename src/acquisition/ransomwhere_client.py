"""Client for the Ransomwhere ransomware payments dataset."""

from __future__ import annotations

import pathlib

from src.acquisition.http_utils import download_file

RANSOMWHERE_EXPORT_URL = "https://api.ransomwhe.re/export"


def download(destination: pathlib.Path) -> pathlib.Path:
    """Downloads the full export of verified ransomware payments.

    Args:
        destination: Target file path for the payments JSON.

    Returns:
        The path to the downloaded file.
    """
    return download_file(RANSOMWHERE_EXPORT_URL, destination)
