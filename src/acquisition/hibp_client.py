"""Client for the Have I Been Pwned (HIBP) public breaches endpoint."""

from __future__ import annotations

import pathlib

from src.acquisition.http_utils import download_file

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"


def download(destination: pathlib.Path) -> pathlib.Path:
    """Downloads the full list of confirmed breaches.

    The breaches listing requires no API key but does require a custom
    User-Agent header, which the shared HTTP helper always sets.

    Args:
        destination: Target file path for the breaches JSON.

    Returns:
        The path to the downloaded file.
    """
    return download_file(HIBP_BREACHES_URL, destination)
