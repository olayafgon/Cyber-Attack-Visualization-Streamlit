"""Client for the CISA Known Exploited Vulnerabilities (KEV) catalog."""

from __future__ import annotations

import pathlib

from src.acquisition.http_utils import download_file

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def download(destination: pathlib.Path) -> pathlib.Path:
    """Downloads the KEV catalog JSON feed.

    Args:
        destination: Target file path for the catalog.

    Returns:
        The path to the downloaded catalog.
    """
    return download_file(KEV_CATALOG_URL, destination)
