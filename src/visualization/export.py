"""Exports every partial chart as PNG for print and HTML for review.

Every figure is built through the same call the app makes, so the printed
chart and the panel on screen carry the same titles and axis labels. Only
the subtitles are dropped, because on paper the caption already carries
those reading notes.

Usage:
    python -m src.visualization.export
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import altair as alt
import pandas as pd

from src.utils import config
from src.visualization import charts
from src.visualization.theme import register_theme

logger = logging.getLogger(__name__)

PREVIEW_DIR = config.DATA_PROCESSED_DIR / "preview"
PNG_SCALE_FACTOR = 2.0

# These print narrower than they render, so their type is scaled up at
# export time to stay readable on paper.
CWE_PRINT_FONT_SCALE = 1.3
CAPTURE_PRINT_FONT_SCALE = 1.4


def _strip_subtitles(node: Any) -> None:
    """Removes the subtitle from every title object found under a spec node."""
    if isinstance(node, dict):
        title = node.get("title")
        if isinstance(title, dict):
            title.pop("subtitle", None)
            title.pop("subtitleColor", None)
        for value in node.values():
            _strip_subtitles(value)
    elif isinstance(node, list):
        for item in node:
            _strip_subtitles(item)


def without_subtitles(chart: alt.TopLevelMixin) -> alt.TopLevelMixin:
    """Returns the same chart with its title subtitles dropped.

    On screen a subtitle carries the reading note of its panel. On paper the
    caption of the figure already says the same thing, so printing both
    repeats it and steals height from the plot. The titles themselves stay
    untouched, so the printed figure and the panel keep naming the same view.

    Args:
        chart: Any chart, including layered and concatenated ones.

    Returns:
        A chart of the same class, rebuilt from the stripped spec.
    """
    spec = chart.to_dict()
    _strip_subtitles(spec)
    return alt.Chart.from_dict(spec)


def build_all_charts() -> dict:
    """Builds every partial chart from the processed datasets.

    Each builder is called exactly as app/app.py calls it, so the exported
    figure and the panel on screen carry the same titles, subtitles and axis
    labels. The breach pair is concatenated here because the app lays its two
    panels out in Streamlit columns instead.

    Returns:
        Mapping from figure basename to Altair chart.
    """
    processed = config.DATA_PROCESSED_DIR
    vulnerabilities = pd.read_parquet(processed / "vulnerabilities.parquet")
    monthly = pd.read_parquet(processed / "vulnerabilities_monthly.parquet")
    incidents = pd.read_parquet(processed / "incidents.parquet")
    breaches = pd.read_parquet(processed / "breaches.parquet")
    payments = pd.read_parquet(processed / "ransomware_payments.parquet")
    return {
        "viz_01_temporal": charts.build_temporal_evolution_chart(monthly),
        "viz_03_mapa": charts.build_geographic_risk_chart(incidents, as_share=True),
        "viz_04_heatmap": charts.build_sector_attack_heatmap(incidents),
        "viz_13_fuentes": charts.build_incidents_by_source_chart(incidents),
        "viz_05_estacionalidad": charts.build_seasonality_chart(monthly),
        "viz_06_cvss_epss": charts.build_cvss_epss_chart(vulnerabilities),
        "viz_07_brechas": charts.build_breach_pair(breaches),
        "viz_08_ransomware": charts.build_ransomware_payments_chart(payments),
        "viz_09_severidad_pct": charts.build_severity_share_chart(monthly),
        "viz_10_paises": charts.build_top_countries_chart(incidents),
        "viz_11_actores": charts.build_actor_type_chart(incidents),
        "viz_12_familias": charts.build_ransomware_families_chart(payments),
    }


def export_cwe_figure() -> None:
    """Renders the CWE ranking with print-scaled type."""
    register_theme(font_scale=CWE_PRINT_FONT_SCALE)
    vulnerabilities = pd.read_parquet(config.DATA_PROCESSED_DIR / "vulnerabilities.parquet")
    chart = without_subtitles(charts.build_cwe_distribution_chart(vulnerabilities))
    png_path = config.FIGURES_DIR / "viz_02_cwe.png"
    chart.save(png_path, scale_factor=PNG_SCALE_FACTOR)
    chart.save(PREVIEW_DIR / "viz_02_cwe.html")
    logger.info("Exported %s", png_path)
    register_theme()


def export_dashboard_captures() -> None:
    """Renders the two linked dashboard pairs in the dark variant."""
    register_theme(dark=True, font_scale=CAPTURE_PRINT_FONT_SCALE)
    processed = config.DATA_PROCESSED_DIR
    monthly = pd.read_parquet(processed / "vulnerabilities_monthly.parquet")
    incidents = pd.read_parquet(processed / "incidents.parquet")
    captures = {
        "viz_dashboard_temporal": charts.build_temporal_pair(monthly),
        "viz_dashboard_geo": charts.build_sector_map_pair(incidents),
    }
    for name, chart in captures.items():
        png_path = config.FIGURES_DIR / f"{name}.png"
        chart.save(png_path, scale_factor=PNG_SCALE_FACTOR)
        logger.info("Exported %s", png_path)
    register_theme(dark=False)


def main() -> int:
    """Renders every chart to FIGURES_DIR (PNG) and a preview dir (HTML)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    register_theme()
    config.FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    PREVIEW_DIR.mkdir(parents=True, exist_ok=True)
    for name, chart in build_all_charts().items():
        png_path = config.FIGURES_DIR / f"{name}.png"
        printable = without_subtitles(chart)
        printable.save(png_path, scale_factor=PNG_SCALE_FACTOR)
        printable.save(PREVIEW_DIR / f"{name}.html")
        logger.info("Exported %s", png_path)
    export_cwe_figure()
    export_dashboard_captures()
    logger.info("All figures exported to %s", config.FIGURES_DIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
