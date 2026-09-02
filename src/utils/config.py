"""Project-wide path and parameter configuration."""

from __future__ import annotations

import os
import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DATA_EXTERNAL_DIR = PROJECT_ROOT / "data" / "external"

# FIGURES_DIR redirects the PNG export to wherever the figures are consumed;
# a relative value resolves against the project root, not the caller's cwd.
FIGURES_DIR = PROJECT_ROOT / pathlib.Path(os.environ.get("FIGURES_DIR", "figures"))

ANALYSIS_START_YEAR = 2015
ANALYSIS_END_YEAR = 2025
