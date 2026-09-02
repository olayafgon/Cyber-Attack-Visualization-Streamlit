"""Shared HTTP helpers for the acquisition clients."""

from __future__ import annotations

import logging
import pathlib

import requests

USER_AGENT = "ciberataques-uned-caso-practico/1.0 (academic data visualization project)"
DEFAULT_TIMEOUT_SECONDS = 60
_DOWNLOAD_CHUNK_BYTES = 1 << 20

logger = logging.getLogger(__name__)


def default_headers() -> dict[str, str]:
    """Returns the base request headers shared by all acquisition clients."""
    return {"User-Agent": USER_AGENT}


def download_file(
    url: str,
    destination: pathlib.Path,
    headers: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> pathlib.Path:
    """Streams a remote file to disk.

    Args:
        url: Source URL.
        destination: Target file path; parent directories are created.
        headers: Extra request headers merged over the defaults.
        timeout: Request timeout in seconds.

    Returns:
        The destination path.

    Raises:
        requests.HTTPError: If the server responds with an error status.
    """
    merged_headers = default_headers() | (headers or {})
    destination.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading %s -> %s", url, destination)
    with requests.get(url, headers=merged_headers, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=_DOWNLOAD_CHUNK_BYTES):
                handle.write(chunk)
    logger.info("Saved %s (%.1f MB)", destination.name, destination.stat().st_size / 1e6)
    return destination


def check_url(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> int:
    """Checks that a URL is reachable without downloading its body.

    Falls back to a streamed GET when the server rejects HEAD requests.

    Args:
        url: URL to probe.
        timeout: Request timeout in seconds.

    Returns:
        The HTTP status code of the probe.
    """
    headers = default_headers()
    response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
    if response.status_code in (403, 404, 405, 501):
        with requests.get(url, headers=headers, timeout=timeout, stream=True) as get_response:
            return get_response.status_code
    return response.status_code
