"""Shared Altair theme: palettes, scales and encoding defaults.

One indigo family drives the whole system. A sequential single-hue ramp
carries magnitude, a four-step indigo-to-warm gradient carries the ordinal
severity bands, a warm accent is reserved for confirmed exploitation, hue is
reserved for nominal variables and neutral grays mark context or missing data.

Every palette here is measured by palette_check.py, which reports how far
apart its colours stay under the three types of colour blindness.
"""

from __future__ import annotations

import copy
import json

import altair as alt

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_LABELS = {
    "LOW": "Baja",
    "MEDIUM": "Media",
    "HIGH": "Alta",
    "CRITICAL": "Crítica",
}

SEVERITY_LABEL_EXPR = f"{json.dumps(SEVERITY_LABELS, ensure_ascii=False)}[datum.label]"

SINGLE_HUE = [
    "#c6ceff",
    "#b4bdf5",
    "#a2adea",
    "#909ce0",
    "#7e8cd5",
    "#6c7dcb",
    "#596dc0",
    "#445fb6",
    "#2c50ab",
]

GRADIENT = ["#485ea1", "#8d5eb1", "#cd56a6", "#fc5983", "#ff7752", "#ffa600"]

_SEVERITY_LIGHT = GRADIENT[:4]
_SEVERITY_DARK = ["#5d71b6", "#a372c7", "#e66dbd", "#ff739a"]

_ACTIVITY_RANGE_DARK = ["#445fb6", "#6c7dcb", "#909ce0", "#b4bdf5", "#dfe4ff"]
_ACTIVITY_RANGE_LIGHT = [SINGLE_HUE[i] for i in (0, 2, 4, 6, 8)]

_ACCENT_LIGHT = ("#485ea1", "#2c50ab")
_ACCENT_DARK = ("#7e8cd5", "#c6ceff")

_KEV_LIGHT = ("#eb9800", "#fc5983")
_KEV_DARK = ("#c98500", "#e04c74")

_CATEGORICAL_LIGHT = [
    "#485ea1",
    "#e69f00",
    "#009e73",
    "#d55e00",
    "#56b4e9",
    "#cc79a7",
]
_CATEGORICAL_DARK = [
    "#697fcc",
    "#f1ab4c",
    "#18c394",
    "#cb762e",
    "#42bffd",
    "#c889ac",
]

_NO_DATA_LIGHT = "#e5e7eb"
_NO_DATA_DARK = "#2e3542"

DARK_BACKGROUND = "#0b1220"
NEUTRAL_GRAY = "#94a3b8"

SEVERITY_COLORS = _SEVERITY_LIGHT
THREAT_GRADIENT = SEVERITY_COLORS
CATEGORICAL_COLORS = _CATEGORICAL_LIGHT
ACCENT_COLOR, ACCENT_STROKE = _ACCENT_LIGHT
KEV_COLOR, KEV_RANSOMWARE_COLOR = _KEV_LIGHT
NO_DATA_COLOR = _NO_DATA_LIGHT

NUMBER_LOCALE = {
    "decimal": ",",
    "thousands": ".",
    "grouping": [3],
    "currency": ["", " €"],
}

_LOCALE_USERMETA = {"embedOptions": {"formatLocale": NUMBER_LOCALE}}

_FONT_STACK = "Inter, 'Segoe UI', system-ui, sans-serif"

_LIGHT_CONFIG = {
    "config": {
        "background": "white",
        "font": _FONT_STACK,
        "view": {"stroke": None},
        "bar": {"cornerRadiusEnd": 2},
        "axis": {
            "gridColor": "#e8edf3",
            "domainColor": "#9aa7b4",
            "tickColor": "#9aa7b4",
            "labelColor": "#334155",
            "titleColor": "#1e293b",
            "labelFontSize": 13,
            "titleFontSize": 14,
        },
        "title": {"fontSize": 17, "fontWeight": "bold", "anchor": "start", "color": "#0f172a"},
        "legend": {
            "labelColor": "#334155",
            "titleColor": "#1e293b",
            "labelFontSize": 13,
            "titleFontSize": 14,
        },
    }
}

_DARK_CONFIG = {
    "config": {
        "background": DARK_BACKGROUND,
        "font": _FONT_STACK,
        "view": {"stroke": None},
        "bar": {"cornerRadiusEnd": 2},
        "axis": {
            "gridColor": "#1c2941",
            "domainColor": "#3d4f6b",
            "tickColor": "#3d4f6b",
            "labelColor": "#c3cfdd",
            "titleColor": "#eef4fb",
            "labelFontSize": 13,
            "titleFontSize": 14,
        },
        "title": {"fontSize": 17, "fontWeight": "bold", "anchor": "start", "color": "#eef4fb"},
        "legend": {
            "labelColor": "#c3cfdd",
            "titleColor": "#eef4fb",
            "labelFontSize": 13,
            "titleFontSize": 14,
        },
    }
}

_dark_mode = False
FONT_SCALE = 1.0


def scaled_font(size: int) -> int:
    """Returns a mark font size adjusted to the active theme scale."""
    return round(size * FONT_SCALE)


def _scale_fonts(config: dict, scale: float) -> dict:
    """Returns a copy of a theme config with every font size scaled."""
    scaled = copy.deepcopy(config)
    for section in ("axis", "legend", "title"):
        entries = scaled["config"][section]
        for key in ("labelFontSize", "titleFontSize", "fontSize"):
            if key in entries:
                entries[key] = round(entries[key] * scale)
    scaled["config"]["title"]["subtitleFontSize"] = round(13 * scale)
    scaled["config"]["legend"]["titleLimit"] = round(200 * scale)
    scaled["config"]["axis"]["labelLimit"] = round(300 * scale)
    return scaled


def register_theme(dark: bool = False, font_scale: float = 1.0) -> None:
    """Enables the project theme and swaps every palette to that variant.

    Args:
        dark: Dark variant, used by the app and by the captured figures.
            The light one is for print.
        font_scale: Multiplies every font size, for exports that print
            smaller than they render, such as the dashboard captures.
    """
    global NO_DATA_COLOR, ACCENT_COLOR, ACCENT_STROKE, _dark_mode, FONT_SCALE
    global CATEGORICAL_COLORS, KEV_COLOR, KEV_RANSOMWARE_COLOR
    global SEVERITY_COLORS, THREAT_GRADIENT
    _dark_mode = dark
    FONT_SCALE = font_scale
    NO_DATA_COLOR = _NO_DATA_DARK if dark else _NO_DATA_LIGHT
    ACCENT_COLOR, ACCENT_STROKE = _ACCENT_DARK if dark else _ACCENT_LIGHT
    CATEGORICAL_COLORS = _CATEGORICAL_DARK if dark else _CATEGORICAL_LIGHT
    KEV_COLOR, KEV_RANSOMWARE_COLOR = _KEV_DARK if dark else _KEV_LIGHT
    SEVERITY_COLORS = _SEVERITY_DARK if dark else _SEVERITY_LIGHT
    THREAT_GRADIENT = SEVERITY_COLORS
    theme_config = _DARK_CONFIG if dark else _LIGHT_CONFIG
    if font_scale != 1.0:
        theme_config = _scale_fonts(theme_config, font_scale)

    def _theme() -> dict:
        return theme_config

    if hasattr(alt, "theme"):
        alt.theme.register("ciberataques", enable=True)(_theme)
    else:
        alt.themes.register("ciberataques", _theme)
        alt.themes.enable("ciberataques")

    alt.renderers.set_embed_options(formatLocale=NUMBER_LOCALE)


def localize(chart: alt.TopLevelMixin) -> alt.TopLevelMixin:
    """Attaches the Spanish number locale to the chart spec itself.

    register_theme covers what Altair renders directly, the PNG export and
    the notebook. A chart handed to another host, such as the Streamlit
    component, travels as a bare spec, and usermeta is the only channel that
    reaches it.

    Args:
        chart: Any top-level Altair chart.

    Returns:
        The same chart, with the embed options attached.
    """
    chart.usermeta = _LOCALE_USERMETA
    return chart


def severity_scale(**kwargs) -> alt.Scale:
    """Builds the ordinal severity scale for the active variant.

    Returns:
        A Scale mapping the four bands of SEVERITY_ORDER to their colors.
    """
    return alt.Scale(domain=SEVERITY_ORDER, range=SEVERITY_COLORS, **kwargs)


def activity_scale(**kwargs) -> alt.Scale:
    """Builds the indigo ramp for counts and magnitudes.

    Args:
        **kwargs: Passed through to alt.Scale (type, domain, ...).

    Returns:
        A Scale for quantitative color encodings, brighter with more activity
        on the dark ground and deeper on white.
    """
    color_range = _ACTIVITY_RANGE_DARK if _dark_mode else _ACTIVITY_RANGE_LIGHT
    return alt.Scale(range=color_range, **kwargs)


def threat_scale(**kwargs) -> alt.Scale:
    """Builds the warm ramp for quantitative severity, such as mean CVSS.

    Returns:
        A Scale for quantitative color encodings.
    """
    return alt.Scale(range=THREAT_GRADIENT, **kwargs)


def ramp_text_colors() -> tuple[str, str]:
    """Ink for text drawn over the activity ramp.

    Returns:
        Colors for the low and high ends, in that order. They swap with the
        variant, because the ramp runs light to dark on white and dark to
        light on navy.
    """
    return ("#eef4fb", "#101828") if _dark_mode else ("#1e293b", "#ffffff")
