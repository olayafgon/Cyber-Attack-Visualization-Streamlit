"""Read and write helpers for the raw, processed, and external data layers."""

from __future__ import annotations

import pathlib

import pandas as pd


def _base_suffix(path: pathlib.Path) -> str:
    """Returns the format suffix of a path, ignoring a trailing .gz."""
    suffixes = path.suffixes
    if suffixes and suffixes[-1] == ".gz" and len(suffixes) > 1:
        return suffixes[-2]
    return path.suffix


def read_dataset(path: pathlib.Path) -> pd.DataFrame:
    """Reads a dataset from disk, inferring the format from the file extension.

    Args:
        path: Path to a CSV, JSON, or Parquet file. CSV files may be
            gzip-compressed (.csv.gz).

    Returns:
        The loaded DataFrame.

    Raises:
        ValueError: If the file extension is not supported.
    """
    suffix = _base_suffix(path)
    if suffix == ".csv":
        return pd.read_csv(path, low_memory=False)
    if suffix == ".json":
        return pd.read_json(path)
    if suffix == ".parquet":
        return pd.read_parquet(path)
    raise ValueError(f"Unsupported dataset format: {path.name}")


def write_dataset(df: pd.DataFrame, path: pathlib.Path) -> None:
    """Writes a dataset to disk, inferring the format from the file extension.

    Args:
        df: DataFrame to persist.
        path: Destination path for a CSV, JSON, or Parquet file.

    Raises:
        ValueError: If the file extension is not supported.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    suffix = _base_suffix(path)
    if suffix == ".csv":
        df.to_csv(path, index=False)
    elif suffix == ".json":
        df.to_json(path, orient="records", indent=2, force_ascii=False)
    elif suffix == ".parquet":
        df.to_parquet(path, index=False)
    else:
        raise ValueError(f"Unsupported dataset format: {path.name}")
