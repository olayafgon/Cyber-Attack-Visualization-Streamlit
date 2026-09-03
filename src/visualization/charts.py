"""Builders for the twelve partial visualizations of the project.

Each one takes a processed DataFrame, aggregates it in pandas down to the
marks actually drawn, and returns a plain Altair chart that the Streamlit
app and the PNG export both reuse.
"""

from __future__ import annotations

import functools
import gettext
import json
from collections.abc import Callable

import altair as alt
import numpy as np
import pandas as pd
import pycountry

from src.utils import config
from src.visualization import theme
from src.visualization.theme import SEVERITY_ORDER

WORLD_TOPOJSON_PATH = config.DATA_EXTERNAL_DIR / "world-110m.json"


def world_countries() -> alt.UrlData:
    """Returns the country geometry, read once and reused by every map.

    Ships with the project rather than coming from a CDN, so the maps render
    without network access.
    """
    global _WORLD_TOPOJSON
    if _WORLD_TOPOJSON is None:
        _WORLD_TOPOJSON = json.loads(WORLD_TOPOJSON_PATH.read_text(encoding="utf-8"))
    return alt.Data(values=_WORLD_TOPOJSON, format=alt.TopoDataFormat(type="topojson", feature="countries"))


_WORLD_TOPOJSON = None

MONTH_LABELS = {
    1: "Ene", 2: "Feb", 3: "Mar", 4: "Abr", 5: "May", 6: "Jun",
    7: "Jul", 8: "Ago", 9: "Sep", 10: "Oct", 11: "Nov", 12: "Dic",
}

CWE_SHORT_NAMES = {
    "CWE-79": "XSS",
    "CWE-89": "Inyección SQL",
    "CWE-787": "Escritura fuera de límites",
    "CWE-20": "Validación de entrada",
    "CWE-125": "Lectura fuera de límites",
    "CWE-22": "Path traversal",
    "CWE-352": "CSRF",
    "CWE-416": "Use after free",
    "CWE-78": "Inyección de comandos OS",
    "CWE-862": "Autorización ausente",
    "CWE-476": "Puntero nulo",
    "CWE-434": "Subida de fichero sin restricción",
    "CWE-119": "Desbordamiento de búfer",
    "CWE-200": "Exposición de información",
    "CWE-287": "Autenticación incorrecta",
    "CWE-502": "Deserialización insegura",
    "CWE-190": "Desbordamiento de entero",
    "CWE-400": "Consumo de recursos",
    "CWE-306": "Autenticación ausente",
    "CWE-94": "Inyección de código",
    "CWE-269": "Gestión de privilegios",
    "CWE-863": "Autorización incorrecta",
    "CWE-918": "SSRF",
    "CWE-77": "Inyección de comandos",
    "CWE-611": "XXE",
    "CWE-843": "Confusión de tipos",
    "CWE-401": "Fuga de memoria",
    "CWE-120": "Copia de búfer",
    "CWE-74": "Inyección",
    "CWE-121": "Desbordamiento de pila",
    "CWE-284": "Control de acceso incorrecto",
}

# Stored in English; these are what the ISO Spanish catalogue gets wrong.
_COUNTRY_OVERRIDES_ES = {
    "Russian Federation": "Rusia",
    "Korea, Republic of": "Corea del Sur",
    "Korea, Democratic People's Republic of": "Corea del Norte",
    "Iran, Islamic Republic of": "Irán",
    "Taiwan, Province of China": "Taiwán",
    "Syrian Arab Republic": "Siria",
    "Viet Nam": "Vietnam",
    "Bolivia, Plurinational State of": "Bolivia",
    "Venezuela, Bolivarian Republic of": "Venezuela",
    "Moldova, Republic of": "Moldavia",
    "Tanzania, United Republic of": "Tanzania",
    "Africa": "África",
    "Caucasus": "Cáucaso",
    "Eastern Europe": "Europa del Este",
    "Asia (region)": "Asia (región)",
    "Europe (region)": "Europa (región)",
    "Global (region)": "Global (región)",
    "Middle East (region)": "Oriente Medio (región)",
    "South Asia (region)": "Asia meridional (región)",
    "Southeast Asia (region)": "Sudeste asiático (región)",
    "Central Asia (region)": "Asia central (región)",
    "Central America (region)": "América Central (región)",
    "Mena Region (region)": "Región MENA",
    "EU (institutions)": "UE (instituciones)",
    "NATO (institutions)": "OTAN (instituciones)",
    "Not available": "No disponible",
    "Unknown": "Desconocido",
}


@functools.lru_cache(maxsize=1)
def _iso_translator() -> Callable[[str], str]:
    """Returns the ISO 3166 Spanish lookup, or identity if it is unavailable."""
    try:
        return gettext.translation(
            "iso3166-1", pycountry.LOCALES_DIR, languages=["es"]
        ).gettext
    except (FileNotFoundError, OSError):
        return lambda name: name


def country_label(name: str | None) -> str | None:
    """Returns the Spanish reading of a stored country name."""
    if not isinstance(name, str):
        return name
    if name in _COUNTRY_OVERRIDES_ES:
        return _COUNTRY_OVERRIDES_ES[name]
    return _iso_translator()(name)


ACTOR_LABELS = {
    "Non-state-group": "Grupo no estatal",
    "State affiliated actor": "Actor afiliado a un Estado",
    "State": "Estado",
    "Individual hacker(s)": "Hacker(s) individual(es)",
    "Not attributed": "Sin atribuir",
    "Unknown": "Otros / Desconocido",
}

ACTOR_FALLBACK = "Otros / Desconocido"

EXPLOITATION_ORDER = [
    "Sin explotación confirmada",
    "Explotada (KEV)",
    "Usada en ransomware",
]


MONTH_ORDER = [MONTH_LABELS[month] for month in range(1, 13)]


def seasonality_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregates CVEs by year and month, with each month's share of its year.

    Args:
        df: Monthly vulnerability aggregate (vulnerabilities_monthly).

    Returns:
        A DataFrame with year, month, month_label, cve_count and share.
    """
    monthly = df.groupby(["year", "month"], observed=True)["cve_count"].sum().reset_index()
    monthly["month_label"] = monthly["month"].map(MONTH_LABELS)
    monthly["share"] = monthly["cve_count"] / monthly.groupby("year")["cve_count"].transform("sum")
    return monthly


def sector_attack_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Builds the complete sector-by-attack grid and its axis orders.

    Grouping alone yields rows only for the observed pairs, which would leave
    holes in the matrix. The grid is completed so every cell draws.

    Args:
        df: Unified incident DataFrame (incidents).

    Returns:
        The completed grid plus the sector and attack orders by descending
        total. The grid carries incident_count (missing where nothing is
        documented), plot_count (a drawable stand-in for those) and
        incident_label for the tooltip.
    """
    counts = df.groupby(["sector", "attack_category"]).size().reset_index(name="incident_count")
    sector_order = (
        counts.groupby("sector")["incident_count"].sum().sort_values(ascending=False).index.tolist()
    )
    attack_order = (
        counts.groupby("attack_category")["incident_count"]
        .sum()
        .sort_values(ascending=False)
        .index.tolist()
    )
    grid = pd.MultiIndex.from_product(
        [sector_order, attack_order], names=["sector", "attack_category"]
    )
    complete = counts.set_index(["sector", "attack_category"]).reindex(grid).reset_index()
    complete["plot_count"] = complete["incident_count"].fillna(1)
    complete["incident_label"] = complete["incident_count"].map(
        lambda value: f"{int(value):,}" if pd.notna(value) else "Sin incidentes documentados"
    )
    return complete, sector_order, attack_order


def build_temporal_evolution_chart(df: pd.DataFrame) -> alt.Chart:
    """Builds the yearly CVE count chart, colored by CVSS severity.

    Args:
        df: Monthly vulnerability aggregate (vulnerabilities_monthly).

    Returns:
        A stacked area chart of CVEs per year by severity band.
    """
    yearly = (
        df.groupby(["year", "cvss_severity"], observed=True)["cve_count"].sum().reset_index()
    )
    yearly["severity_label"] = yearly["cvss_severity"].map(theme.SEVERITY_LABELS)
    return (
        alt.Chart(yearly)
        .mark_area()
        .encode(
            x=alt.X("year:O", title="Año de publicación", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("cve_count:Q", title="CVEs publicadas", stack="zero"),
            color=alt.Color(
                "cvss_severity:N",
                title="Severidad CVSS",
                scale=theme.severity_scale(),
                sort=SEVERITY_ORDER,
                legend=alt.Legend(labelExpr=theme.SEVERITY_LABEL_EXPR),
            ),
            order=alt.Order("severity_rank:Q"),
            tooltip=[
                alt.Tooltip("year:O", title="Año"),
                alt.Tooltip("severity_label:N", title="Severidad"),
                alt.Tooltip("cve_count:Q", title="CVEs", format=","),
            ],
        )
        .transform_calculate(severity_rank=f"indexof({SEVERITY_ORDER}, datum.cvss_severity)")
        .properties(
            width=640,
            height=300,
            title=alt.TitleParams(
                "Evolución anual de vulnerabilidades por severidad",
                subtitle=CVSS_BREAK_NOTE,
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    )


def top_weaknesses(df: pd.DataFrame, top_n: int) -> pd.DataFrame:
    """Ranks the most frequent known CWE categories with their mean CVSS.

    Args:
        df: Enriched vulnerability DataFrame (vulnerabilities).
        top_n: Number of CWE categories to keep.

    Returns:
        A DataFrame with cwe_id, cve_count, cvss_mean and a display label.
    """
    known = df[df["cwe_id"] != "Unknown"]
    top = (
        known.groupby("cwe_id")
        .agg(cve_count=("cve_id", "count"), cvss_mean=("cvss_score", "mean"))
        .nlargest(top_n, "cve_count")
        .reset_index()
    )
    top["label"] = top["cwe_id"].map(
        lambda cwe: f"{cwe} · {CWE_SHORT_NAMES[cwe]}" if cwe in CWE_SHORT_NAMES else cwe
    )
    return top


def build_cwe_distribution_chart(
    df: pd.DataFrame, top_n: int = 20, selection: alt.Parameter | None = None
) -> alt.Chart:
    """Builds a horizontal bar chart of the most frequent CWE categories.

    Args:
        df: Enriched vulnerability DataFrame (vulnerabilities).
        top_n: Number of CWE categories to display.
        selection: Optional point selection to carry. When given, the chart
            adds it and dims the bars outside it, so the filter driven from
            here is visible on the chart that drives it.

    Returns:
        An Altair chart ranking CWE categories by frequency, colored by
        average CVSS score.
    """
    top = top_weaknesses(df, top_n)
    encodings = {
        "y": alt.Y(
            "label:N",
            title=None,
            sort="-x",
            axis=alt.Axis(labelLimit=380, labelOverlap=False),
        ),
        "x": alt.X("cve_count:Q", title="Número de CVEs"),
        "color": alt.Color(
            "cvss_mean:Q",
            title="CVSS medio",
            scale=theme.threat_scale(domain=[4, 9]),
        ),
        "tooltip": [
            alt.Tooltip("cwe_id:N", title="CWE"),
            alt.Tooltip("cve_count:Q", title="CVEs", format=","),
            alt.Tooltip("cvss_mean:Q", title="CVSS medio", format=".2f"),
        ],
    }
    if selection is not None:
        encodings["opacity"] = alt.condition(selection, alt.value(1.0), alt.value(0.3))
    chart = alt.Chart(top).mark_bar().encode(**encodings)
    if selection is not None:
        chart = chart.add_params(selection)
    return chart.properties(
        width=560,
        height=540,
        title=f"Top {top_n} tipos de debilidad (CWE) por número de CVEs",
    )


def build_geographic_risk_chart(df: pd.DataFrame, as_share: bool = False) -> alt.Chart:
    """Builds a choropleth map of incidents by country.

    The counts drive the choropleth and the geometry arrives through a
    lookup, deliberately: if both layers shared one data source Altair would
    hoist it to the top of the spec, where Streamlit serialises it as Arrow
    and the TopoJSON does not survive the round trip. The map then renders
    empty with an ArrowTypeError in the log.

    Args:
        df: Unified incident DataFrame (incidents).
        as_share: Encode each country's share of the frame instead of the
            raw count, which is what the sector-filtered view needs.

    Returns:
        A layered map, with countries lacking data on a neutral background.
    """
    by_country = (
        df.dropna(subset=["country_numeric"])
        .groupby(["country_numeric", "country_name"])
        .size()
        .reset_index(name="incident_count")
    )
    by_country["country_numeric"] = by_country["country_numeric"].astype(int)
    by_country["country_label"] = by_country["country_name"].map(country_label)
    if as_share:
        total = by_country["incident_count"].sum()
        by_country["share"] = by_country["incident_count"] / total if total else 0.0
    countries = world_countries()
    background = (
        alt.Chart(countries)
        .mark_geoshape(fill=theme.NO_DATA_COLOR, stroke="white", strokeWidth=0.4)
        .transform_filter("datum.id !== 10")
    )
    color = (
        alt.Color(
            "share:Q",
            title="% del total",
            scale=theme.activity_scale(type="log"),
            legend=alt.Legend(format=".1%"),
        )
        if as_share
        else alt.Color(
            "incident_count:Q", title="Incidentes", scale=theme.activity_scale(type="log")
        )
    )
    tooltip = [
        alt.Tooltip("country_label:N", title="País"),
        alt.Tooltip("incident_count:Q", title="Incidentes", format=","),
    ]
    if as_share:
        tooltip.append(alt.Tooltip("share:Q", title="% del total", format=".1%"))
    choropleth = (
        alt.Chart(by_country)
        .transform_lookup(
            lookup="country_numeric",
            from_=alt.LookupData(countries, "id"),
            as_="geometry",
        )
        .mark_geoshape(stroke="white", strokeWidth=0.4)
        .encode(shape=alt.Shape("geometry:G"), color=color, tooltip=tooltip)
    )
    title = (
        "Reparto por país de la selección (porcentaje)"
        if as_share
        else "Incidentes de ciberseguridad por país (2015-2025)"
    )
    return (
        (background + choropleth)
        .project(type="equalEarth")
        .properties(
            width=680,
            height=320,
            title=alt.TitleParams(
                title,
                subtitle="En gris, países sin incidentes documentados",
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    )


def build_sector_attack_heatmap(
    df: pd.DataFrame, selection: alt.Parameter | None = None
) -> alt.Chart:
    """Builds a heatmap crossing sector and attack category.

    Args:
        df: Unified incident DataFrame (incidents).
        selection: Optional point selection to carry. It dims the cells
            outside the selection so the filter driven from here is visible.

    Returns:
        A heatmap of incident counts, each documented cell labelled with its
        figure, over a neutral grid.
    """
    counts, sector_order, attack_order = sector_attack_frame(df)
    color = alt.condition(
        "isValid(datum.incident_count)",
        alt.Color(
            "plot_count:Q",
            title="Incidentes",
            scale=theme.activity_scale(type="log"),
        ),
        alt.value(theme.NO_DATA_COLOR),
    )
    encodings = {
        "y": alt.Y(
            "sector:N",
            title=None,
            sort=sector_order,
            axis=alt.Axis(labelOverlap=False, labelLimit=300),
        ),
        "x": alt.X(
            "attack_category:N",
            title="Categoría de ataque",
            sort=attack_order,
            axis=alt.Axis(labelAngle=-35, labelOverlap=False),
        ),
        "color": color,
        "tooltip": [
            alt.Tooltip("sector:N", title="Sector"),
            alt.Tooltip("attack_category:N", title="Ataque"),
            alt.Tooltip("incident_label:N", title="Incidentes"),
        ],
    }
    if selection is not None:
        encodings["opacity"] = alt.condition(selection, alt.value(1.0), alt.value(0.3))
    chart = alt.Chart(counts).mark_rect(stroke="white", strokeWidth=1).encode(**encodings)
    if selection is not None:
        chart = chart.add_params(selection)
    low_ink, high_ink = theme.ramp_text_colors()
    labels = (
        alt.Chart(counts.dropna(subset=["incident_count"]))
        .mark_text(fontSize=theme.scaled_font(11))
        .encode(
            x=encodings["x"],
            y=encodings["y"],
            text=alt.Text("incident_count:Q", format=","),
            color=alt.condition(
                "datum.plot_count > 26", alt.value(high_ink), alt.value(low_ink)
            ),
        )
    )
    return alt.layer(chart, labels).properties(
        width=560,
        height=340,
        title=alt.TitleParams(
            "Incidentes por sector y categoría de ataque",
            subtitle="Las celdas neutras no tienen incidentes documentados",
            subtitleColor=theme.NEUTRAL_GRAY,
        ),
    )


def build_seasonality_chart(
    df: pd.DataFrame, year_filter: alt.Parameter | None = None
) -> alt.Chart:
    """Builds the year-month heatmap of CVE publication.

    Args:
        df: Monthly vulnerability aggregate (vulnerabilities_monthly).
        year_filter: Optional interval selection over the year axis. When
            given, the cells filter to the brushed range and the static peak
            marker is dropped, since the series maximum may fall outside it.

    Returns:
        A year-month heatmap of each month's weight within its own year.
    """
    monthly = seasonality_frame(df)
    cells = (
        alt.Chart(monthly)
        .mark_rect(stroke="white", strokeWidth=1)
        .encode(
            x=alt.X("year:O", title="Año", axis=alt.Axis(labelAngle=0)),
            y=alt.Y(
                "month_label:N",
                title=None,
                sort=MONTH_ORDER,
                axis=alt.Axis(labelOverlap=False),
            ),
            color=alt.Color(
                "share:Q",
                title="% de su año",
                scale=theme.activity_scale(),
                legend=alt.Legend(format=".1%"),
            ),
            tooltip=[
                alt.Tooltip("year:O", title="Año"),
                alt.Tooltip("month_label:N", title="Mes"),
                alt.Tooltip("cve_count:Q", title="CVEs", format=","),
                alt.Tooltip("share:Q", title="% de su año", format=".1%"),
            ],
        )
    )
    if year_filter is not None:
        return cells.transform_filter(year_filter).properties(
            width=560,
            height=300,
            title=alt.TitleParams(
                "Estacionalidad mensual de publicación de CVEs",
                subtitle="Cada mes sobre el total de su año; un reparto uniforme daría 8,3 %",
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    peak = monthly.nlargest(1, "share")
    marker = (
        alt.Chart(peak)
        .mark_rect(fill=None, stroke=theme.NEUTRAL_GRAY, strokeWidth=2.5)
        .encode(
            x=alt.X("year:O", sort=None),
            y=alt.Y("month_label:N", sort=MONTH_ORDER),
            tooltip=[
                alt.Tooltip("year:O", title="Año"),
                alt.Tooltip("month_label:N", title="Mes"),
                alt.Tooltip("share:Q", title="Máximo relativo de la serie", format=".1%"),
            ],
        )
    )
    return (cells + marker).properties(
        width=560,
        height=300,
        title=alt.TitleParams(
            "Estacionalidad mensual de publicación de CVEs",
            subtitle=[
                "Cada mes sobre el total de su año; un reparto uniforme daría 8,3 %",
                "La celda recuadrada es el máximo de la serie",
            ],
            subtitleColor=theme.NEUTRAL_GRAY,
        ),
    )


CVSS_BREAK_NOTE = (
    "2015 puntúa casi entero en CVSS v2, así que el salto hasta 2016 "
    "es el cambio de escala y no del panorama"
)


def _jitter_scores(frame: pd.DataFrame, spread: float = 0.04) -> pd.DataFrame:
    """Spreads CVSS scores inside their own grid step for plotting.

    Args:
        frame: Vulnerability rows carrying cvss_score.
        spread: Half-width of the offset, below half the 0.1 CVSS step so a
            mark never drifts into a neighbouring score.

    Returns:
        The frame with a cvss_plot column. The seed is fixed so the exported
        figure and the app draw the same cloud.
    """
    offsets = np.random.default_rng(42).uniform(-spread, spread, len(frame))
    centers = frame["cvss_score"].clip(spread, 10.0 - spread)
    return frame.assign(cvss_plot=centers + offsets)


def _thousands(value: int) -> str:
    """Formats an integer with the Spanish thousands separator."""
    return f"{value:,}".replace(",", ".")


def _millions(value: float) -> str:
    """Formats a magnitude in millions, with a decimal only under ten."""
    text = f"{value:,.1f}" if value < 10 else f"{value:,.0f}"
    return text.replace(",", "\u0000").replace(".", ",").replace("\u0000", ".")


def build_cvss_epss_chart(
    df: pd.DataFrame,
    background_sample: int = 4000,
    selection: alt.Parameter | None = None,
) -> alt.Chart:
    """Builds the severity-versus-exploitability scatter, KEV highlighted.

    A fixed-seed sample of non-exploited CVEs forms the gray context and the
    KEV catalogue is drawn whole on top, colored by known ransomware use.
    Both layers use the same mark size and opacity.

    Args:
        df: Enriched vulnerability DataFrame (vulnerabilities).
        background_sample: Number of non-KEV CVEs sampled for context.
        selection: Optional point selection over cwe_id, defined by a sibling
            view. Only the point layers filter on it; the threshold rule has
            no cwe_id and an active selection would blank it out.

    Returns:
        A layered Altair scatter chart.
    """
    scored = df[df["epss_score"] > 0].copy()
    context_pool = scored[~scored["is_kev"]]
    non_kev = context_pool.sample(
        n=min(background_sample, len(context_pool)), random_state=42
    ).copy()
    kev = scored[scored["is_kev"]].copy()
    non_kev = _jitter_scores(non_kev)
    kev = _jitter_scores(kev)
    exploitation_order = EXPLOITATION_ORDER
    non_kev["exploitation"] = exploitation_order[0]
    kev["exploitation"] = kev["kev_ransomware"].map(
        {True: exploitation_order[2], False: exploitation_order[1]}
    )
    exploitation_color = alt.Color(
        "exploitation:N",
        title=None,
        scale=alt.Scale(
            domain=exploitation_order,
            range=[theme.NEUTRAL_GRAY, theme.KEV_COLOR, theme.KEV_RANSOMWARE_COLOR],
        ),
        legend=alt.Legend(orient="bottom", direction="horizontal", labelLimit=200),
    )
    x_axis = alt.X("cvss_plot:Q", title="Gravedad (CVSS)", scale=alt.Scale(domain=[0, 10]))
    y_axis = alt.Y(
        "epss_score:Q",
        title="Probabilidad de explotación (EPSS, escala log)",
        scale=alt.Scale(type="log", domain=[0.0004, 1], nice=False),
    )
    background = (
        alt.Chart(non_kev)
        .mark_circle(size=14, opacity=0.25)
        .encode(x=x_axis, y=y_axis, color=exploitation_color)
    )
    if selection is not None:
        background = background.transform_filter(selection)
    highlights = (
        alt.Chart(kev)
        .mark_circle(size=14, opacity=0.38)
        .encode(
            x=x_axis,
            y=y_axis,
            color=exploitation_color,
            tooltip=[
                alt.Tooltip("cve_id:N", title="CVE"),
                alt.Tooltip("cvss_score:Q", title="CVSS", format=".1f"),
                alt.Tooltip("epss_score:Q", title="EPSS", format=".4f"),
                alt.Tooltip("cwe_id:N", title="CWE"),
                alt.Tooltip("year:O", title="Año"),
            ],
        )
    )
    if selection is not None:
        highlights = highlights.transform_filter(selection)
    reference = pd.DataFrame(
        {"cvss": [9.0], "epss": [0.0005], "label": ["CVSS 9, umbral de crítica"]}
    )
    threshold = (
        alt.Chart(reference)
        .mark_rule(color=theme.NEUTRAL_GRAY, strokeDash=[4, 4], strokeWidth=1)
        .encode(x=alt.X("cvss:Q"))
    )
    threshold_label = (
        alt.Chart(reference)
        .mark_text(align="right", dx=-5, dy=-6, fontSize=11, fontStyle="italic",
                   color=theme.NEUTRAL_GRAY, baseline="bottom")
        .encode(x=alt.X("cvss:Q"), y=alt.Y("epss:Q"), text="label:N")
    )
    subtitle = [
        f"Capa gris, muestra de {_thousands(len(non_kev))} de "
        f"{_thousands(len(context_pool))} CVEs sin explotación confirmada",
        f"En color, las {_thousands(len(kev))} del catálogo KEV al completo, "
        "con desplazamiento horizontal para separar puntuaciones repetidas",
    ]
    return (background + threshold + highlights + threshold_label).properties(
        width=620,
        height=380,
        title=alt.TitleParams(
            "Gravedad frente a probabilidad de explotación",
            subtitle=subtitle,
            subtitleColor=theme.NEUTRAL_GRAY,
        ),
    )



def build_incidents_by_source_chart(df: pd.DataFrame) -> alt.Chart:
    """Builds the yearly incident count split by source.

    Args:
        df: Unified incident DataFrame (incidents).

    Returns:
        A grouped bar chart of incidents per year and source.
    """
    yearly = df.groupby(["year", "source"]).size().reset_index(name="incident_count")
    return (
        alt.Chart(yearly)
        .mark_bar()
        .encode(
            x=alt.X("year:O", title="Año", axis=alt.Axis(labelAngle=0)),
            xOffset=alt.XOffset("source:N"),
            y=alt.Y("incident_count:Q", title="Incidentes documentados"),
            color=alt.Color(
                "source:N",
                title="Fuente",
                scale=alt.Scale(range=theme.CATEGORICAL_COLORS[:2]),
            ),
            tooltip=[
                alt.Tooltip("year:O", title="Año"),
                alt.Tooltip("source:N", title="Fuente"),
                alt.Tooltip("incident_count:Q", title="Incidentes", format=","),
            ],
        )
        .properties(
            width=600,
            height=260,
            title=alt.TitleParams(
                "Incidentes por año y fuente",
                subtitle="La serie mide esfuerzo de documentación, no incidencia",
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    )


def _breach_totals(df: pd.DataFrame, key: str) -> pd.DataFrame:
    """Totals the exposed accounts of a breach frame over one dimension."""
    totals = df.groupby(key)["pwn_count"].sum().div(1e6).reset_index()
    totals.columns = [key, "accounts_millions"]
    totals["label"] = totals["accounts_millions"].map(_millions)
    return totals


def build_breach_sector_chart(df: pd.DataFrame) -> alt.Chart:
    """Builds the ranking of exposed accounts by sector.

    Args:
        df: Cleaned HIBP breach DataFrame (breaches).

    Returns:
        A horizontal bar chart, sectors ranked by total.
    """
    totals = _breach_totals(df, "sector")
    order = totals.sort_values("accounts_millions", ascending=False)["sector"].tolist()
    y = alt.Y(
        "sector:N", title=None, sort=order,
        axis=alt.Axis(labelLimit=200, labelOverlap=False),
    )
    x = alt.X(
        "accounts_millions:Q",
        title="Cuentas expuestas (millones)",
        axis=alt.Axis(tickCount=4),
    )
    bars = alt.Chart(totals).mark_bar(color=theme.ACCENT_COLOR).encode(
        y=y, x=x,
        tooltip=[
            alt.Tooltip("sector:N", title="Sector"),
            alt.Tooltip("accounts_millions:Q", title="Millones", format=",.0f"),
        ],
    )
    labels = (
        alt.Chart(totals)
        .mark_text(align="left", dx=4, fontSize=11, color=theme.NEUTRAL_GRAY)
        .encode(y=y, x=x, text="label:N")
    )
    return alt.layer(bars, labels).properties(
        width=300,
        height=230,
        title="Cuentas expuestas en brechas, por sector",
    )


def build_breach_year_chart(df: pd.DataFrame, axis_title: str | None = None) -> alt.Chart:
    """Builds the yearly profile of exposed accounts.

    Args:
        df: Cleaned HIBP breach DataFrame (breaches).
        axis_title: Label of the value axis.

    Returns:
        A bar chart of exposed accounts per year.
    """
    totals = _breach_totals(df, "year")
    x = alt.X("year:O", title=None, axis=alt.Axis(labelAngle=0))
    y = alt.Y("accounts_millions:Q", title=axis_title)
    bars = alt.Chart(totals).mark_bar(color=theme.ACCENT_COLOR).encode(
        x=x, y=y,
        tooltip=[
            alt.Tooltip("year:O", title="Año"),
            alt.Tooltip("accounts_millions:Q", title="Millones", format=",.0f"),
        ],
    )
    labels = (
        alt.Chart(totals)
        .mark_text(dy=-7, fontSize=10, color=theme.NEUTRAL_GRAY)
        .encode(x=x, y=y, text="label:N")
    )
    return alt.layer(bars, labels).properties(
        width=330,
        height=230,
        title="Cuentas expuestas en brechas, por año",
    )


def build_breach_pair(df: pd.DataFrame) -> alt.HConcatChart:
    """Pairs the two breach views as a single figure.

    The Streamlit app lays the same two panels out in its own columns, so
    each one stretches with the window. Both are built with the arguments the
    app passes, keeping the captured figure and the screen in step.

    Args:
        df: Cleaned HIBP breach DataFrame (breaches).

    Returns:
        The two panels side by side, each with its own title.
    """
    return alt.hconcat(
        build_breach_sector_chart(df),
        build_breach_year_chart(df, axis_title="Cuentas expuestas (millones)"),
        spacing=28,
    )


def build_ransomware_payments_chart(df: pd.DataFrame, annotate: bool = True) -> alt.Chart:
    """Builds the quarterly ransomware payments chart.

    Args:
        df: Flattened ransomware payment DataFrame (ransomware_payments).
        annotate: Highlight the 2020-2021 wave, the finding the chart exists
            to show. Disabled when the filtered window hides it.

    Returns:
        An Altair bar chart of quarterly paid amounts in USD.
    """
    quarters = df.set_index("date").resample("QS")
    quarterly = quarters.agg(amount_usd=("amount_usd", "sum"), payments=("amount_usd", "count"))
    quarterly["top_family"] = quarters["family"].agg(
        lambda families: families.value_counts().idxmax() if len(families) else None
    )
    quarterly = quarterly.reset_index()
    quarterly["amount_musd"] = quarterly["amount_usd"] / 1e6
    bars = (
        alt.Chart(quarterly)
        .mark_bar(color=theme.ACCENT_COLOR, width={"band": 0.8})
        .encode(
            x=alt.X("yearquarter(date):T", title="Trimestre", axis=alt.Axis(format="%Y")),
            y=alt.Y("amount_musd:Q", title="Pagos de rescate (millones USD)"),
            tooltip=[
                alt.Tooltip("date:T", title="Trimestre", format="%Y-%m"),
                alt.Tooltip("amount_musd:Q", title="Millones USD", format=",.1f"),
                alt.Tooltip("payments:Q", title="Nº de pagos"),
                alt.Tooltip("top_family:N", title="Familia dominante"),
            ],
        )
    )
    layers = [bars]
    covers_wave = quarterly["date"].dt.year.between(2020, 2021).any()
    if annotate and covers_wave:
        span = pd.DataFrame({"start": [pd.Timestamp("2020-01-01")], "end": [pd.Timestamp("2021-12-31")]})
        share = (
            quarterly.loc[quarterly["date"].dt.year.between(2020, 2021), "amount_usd"].sum()
            / quarterly["amount_usd"].sum()
        )
        band = (
            alt.Chart(span)
            .mark_rect(color=theme.NEUTRAL_GRAY, opacity=0.14)
            .encode(x=alt.X("start:T"), x2=alt.X2("end:T"))
        )
        label = (
            alt.Chart(pd.DataFrame({
                "date": [quarterly["date"].min()],
                "text": [f"Ola 2020-2021 · {share:.0%} del total"],
            }))
            .mark_text(align="left", dx=4, fontSize=11, fontStyle="italic",
                       color=theme.NEUTRAL_GRAY, baseline="top")
            .encode(x=alt.X("date:T"), y=alt.value(4), text="text:N")
        )
        layers = [band, bars, label]
    return alt.layer(*layers).properties(
        width=640, height=220, title="Pagos de ransomware verificados por trimestre"
    )


def build_severity_share_chart(df: pd.DataFrame) -> alt.Chart:
    """Builds the 100 %-stacked severity composition per year.

    Args:
        df: Monthly vulnerability aggregate (vulnerabilities_monthly).

    Returns:
        A 100%-stacked area chart of severity shares.
    """
    yearly = (
        df.groupby(["year", "cvss_severity"], observed=True)["cve_count"].sum().reset_index()
    )
    yearly["severity_label"] = yearly["cvss_severity"].map(theme.SEVERITY_LABELS)
    return (
        alt.Chart(yearly)
        .mark_area()
        .encode(
            x=alt.X("year:O", title="Año de publicación", axis=alt.Axis(labelAngle=0)),
            y=alt.Y(
                "cve_count:Q",
                title="Proporción de CVEs",
                stack="normalize",
                axis=alt.Axis(format="%"),
            ),
            color=alt.Color(
                "cvss_severity:N",
                title="Severidad CVSS",
                scale=theme.severity_scale(),
                sort=SEVERITY_ORDER,
                legend=alt.Legend(labelExpr=theme.SEVERITY_LABEL_EXPR),
            ),
            order=alt.Order("severity_rank:Q"),
            tooltip=[
                alt.Tooltip("year:O", title="Año"),
                alt.Tooltip("severity_label:N", title="Severidad"),
                alt.Tooltip("cve_count:Q", title="CVEs", format=","),
            ],
        )
        .transform_calculate(severity_rank=f"indexof({SEVERITY_ORDER}, datum.cvss_severity)")
        .properties(
            width=640,
            height=300,
            title=alt.TitleParams(
                "Composición anual por severidad (porcentaje)",
                subtitle=CVSS_BREAK_NOTE,
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    )


def build_top_countries_chart(df: pd.DataFrame, top_n: int = 15) -> alt.Chart:
    """Builds the country ranking that complements the choropleth.

    Args:
        df: Unified incident DataFrame (incidents).
        top_n: Number of countries to display.

    Returns:
        A horizontal bar chart of incidents per country.
    """
    top = (
        df.dropna(subset=["country_iso2"])
        .groupby("country_name")
        .size()
        .nlargest(top_n)
        .reset_index(name="incident_count")
    )
    top["country_label"] = top["country_name"].map(country_label)
    y_axis = alt.Y(
        "country_label:N",
        title=None,
        sort="-x",
        axis=alt.Axis(labelLimit=260, labelOverlap=False),
    )
    x_axis = alt.X("incident_count:Q", title="Número de incidentes")
    bars = (
        alt.Chart(top)
        .mark_bar(color=theme.ACCENT_COLOR)
        .encode(
            y=y_axis,
            x=x_axis,
            tooltip=[
                alt.Tooltip("country_label:N", title="País"),
                alt.Tooltip("incident_count:Q", title="Incidentes", format=","),
            ],
        )
    )
    labels = (
        alt.Chart(top)
        .mark_text(align="left", dx=4, fontSize=12, color=theme.NEUTRAL_GRAY)
        .encode(y=y_axis, x=x_axis, text=alt.Text("incident_count:Q", format=","))
    )
    return (
        alt.layer(bars, labels)
        .properties(width=560, height=460, title=f"Top {top_n} países por incidentes documentados")
    )


def build_actor_type_chart(df: pd.DataFrame) -> alt.Chart:
    """Builds the attributed-actor evolution chart from EuRepoC incidents.

    Args:
        df: Unified incident DataFrame (incidents); only EuRepoC rows carry
            actor attribution.

    Returns:
        A stacked bar chart of incidents per year and actor type.
    """
    eurepoc = df[(df["source"] == "EuRepoC") & df["actor_raw"].notna()].copy()
    eurepoc["actor"] = eurepoc["actor_raw"].map(ACTOR_LABELS).fillna(ACTOR_FALLBACK)
    counts = eurepoc.groupby(["year", "actor"]).size().reset_index(name="incident_count")
    actor_order = (
        counts.groupby("actor")["incident_count"].sum().sort_values(ascending=False).index.tolist()
    )
    return (
        alt.Chart(counts)
        .mark_bar()
        .encode(
            x=alt.X("year:O", title="Año", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("incident_count:Q", title="Incidentes (EuRepoC)"),
            color=alt.Color(
                "actor:N",
                title="Tipo de actor",
                scale=alt.Scale(domain=actor_order, range=theme.CATEGORICAL_COLORS[: len(actor_order)]),
            ),
            order=alt.Order("actor_rank:Q"),
            tooltip=[
                alt.Tooltip("year:O", title="Año"),
                alt.Tooltip("actor:N", title="Actor"),
                alt.Tooltip("incident_count:Q", title="Incidentes", format=","),
            ],
        )
        .transform_calculate(actor_rank=f"indexof({json.dumps(actor_order)}, datum.actor)")
        .properties(width=560, height=320, title="Incidentes por tipo de actor iniciador (EuRepoC)")
    )


def _log_domain(values: pd.Series, pad: float = 0.2) -> list[float]:
    """Returns a log-scale domain padded around the observed range.

    Args:
        values: The positive quantities to be plotted.
        pad: Padding on each side, in decades.

    Returns:
        The lower and upper bounds of the scale.
    """
    low, high = np.log10(values.min()), np.log10(values.max())
    return [float(10 ** (low - pad)), float(10 ** (high + pad))]


def _label_offsets(
    frame: pd.DataFrame, x_field: str, y_field: str, threshold: float = 0.12
) -> list[int]:
    """Places each label above its mark, dropping it below on a collision.

    Distance is measured in decades, because on log axes two families a
    factor apart sit equally far on screen wherever they are.

    Args:
        frame: Rows in the order they will be drawn.
        x_field: Column carrying the horizontal quantity.
        y_field: Column carrying the vertical quantity.
        threshold: How close in decades counts as a collision.

    Returns:
        The vertical offset in pixels for each row.
    """
    coords = np.column_stack(
        (np.log10(frame[x_field].to_numpy()), np.log10(frame[y_field].to_numpy()))
    )
    above, below = -13, 19
    offsets: list[int] = []
    for index, point in enumerate(coords):
        clashes = any(
            offsets[other] == above
            and np.hypot(*(point - coords[other])) < threshold
            for other in range(index)
        )
        offsets.append(below if clashes else above)
    return offsets


def build_ransomware_families_chart(df: pd.DataFrame, top_n: int = 12) -> alt.Chart:
    """Builds the payments-versus-revenue scatter for ransomware families.

    Args:
        df: Flattened ransomware payment DataFrame (ransomware_payments).
        top_n: Number of families (by revenue) to display.

    Returns:
        A labeled scatter chart on log-log axes.
    """
    families = (
        df[df["family"].notna() & (df["family"] != "Unlabeled")]
        .groupby("family")
        .agg(payments=("amount_usd", "count"), amount_usd=("amount_usd", "sum"))
        .nlargest(top_n, "amount_usd")
        .reset_index()
    )
    families["amount_musd"] = families["amount_usd"] / 1e6
    families["label_dy"] = _label_offsets(families, "payments", "amount_musd")
    x_domain = _log_domain(families["payments"])
    y_domain = _log_domain(families["amount_musd"])
    base = alt.Chart(families).encode(
        x=alt.X(
            "payments:Q",
            title="Número de pagos (escala log)",
            scale=alt.Scale(type="log", domain=x_domain, nice=False),
        ),
        y=alt.Y(
            "amount_musd:Q",
            title="Importe total (millones USD, escala log)",
            scale=alt.Scale(type="log", domain=y_domain, nice=False),
        ),
        tooltip=[
            alt.Tooltip("family:N", title="Familia"),
            alt.Tooltip("payments:Q", title="Pagos", format=","),
            alt.Tooltip("amount_musd:Q", title="Millones USD", format=",.1f"),
        ],
    )
    points = base.mark_circle(size=90, color=theme.ACCENT_COLOR, stroke=theme.ACCENT_STROKE, strokeWidth=0.5)
    labels = [
        base.transform_filter(f"datum.label_dy === {offset}")
        .mark_text(align="center", dy=offset, fontSize=11, color=theme.NEUTRAL_GRAY)
        .encode(text="family:N")
        for offset in sorted(set(families["label_dy"]))
    ]
    return alt.layer(points, *labels).properties(
        width=600, height=340, title=f"Familias de ransomware, pagos frente a recaudación (top {top_n})"
    )


# --- Linked pairs composed for static capture ------------------------------


def build_temporal_pair(monthly: pd.DataFrame) -> alt.HConcatChart:
    """Builds the linked temporal-seasonality pair (year interval brush).

    Args:
        monthly: Monthly vulnerability aggregate (vulnerabilities_monthly).

    Returns:
        A side-by-side pair sharing a year brush. Both carry the same year
        axis, so the brushed range and its monthly detail sit on one row.
    """
    year_brush = alt.selection_interval(encodings=["x"])
    temporal = (
        build_temporal_evolution_chart(monthly)
        .add_params(year_brush)
        .properties(
            width=470,
            height=320,
            title=alt.TitleParams(
                "Evolución anual por severidad (arrastra para filtrar)",
                subtitle=CVSS_BREAK_NOTE,
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    )
    seasonal = build_seasonality_chart(monthly, year_filter=year_brush).properties(
        width=470,
        height=320,
        title=alt.TitleParams(
            "Estacionalidad mensual (filtrada por el rango)",
            subtitle="Cada mes sobre el total de su año; uniforme sería 8,3 %",
            subtitleColor=theme.NEUTRAL_GRAY,
        ),
    )
    return alt.hconcat(temporal, seasonal, spacing=32)


def build_sector_map_pair(incidents: pd.DataFrame) -> alt.HConcatChart:
    """Builds the linked heatmap-choropleth pair (sector point selection).

    The map embeds row-level incidents on purpose, so the selection can
    re-aggregate country shares client-side. An empty selection means every
    sector, so the map opens on the whole picture and clicking narrows it.
    The colour scale is resolved independently, or the incident counts of
    the heatmap would share a domain with the proportions of the map.

    Args:
        incidents: Unified incident DataFrame (incidents).

    Returns:
        A side-by-side pair sharing the sector selection.
    """
    alt.data_transformers.disable_max_rows()
    sector_click = alt.selection_point(fields=["sector"], toggle="true")
    heatmap = build_sector_attack_heatmap(
        incidents, selection=sector_click
    ).properties(
        width=430,
        height=300,
        title=alt.TitleParams(
            "Sector × ataque (clic para elegir el sector del mapa)",
            subtitle="Las celdas neutras no tienen incidentes documentados",
            subtitleColor=theme.NEUTRAL_GRAY,
        ),
    )
    return alt.hconcat(
        heatmap,
        _sector_share_map(incidents, sector_click),
        spacing=32,
    ).resolve_scale(color="independent")


def _sector_share_map(incidents: pd.DataFrame, sector_click: alt.Parameter) -> alt.LayerChart:
    """Choropleth of each country's share of the selected sector.

    The aggregation runs inside the Vega spec so the selection recomputes
    shares client-side: transform_aggregate counts incidents per country,
    joinaggregate totals the selection and the ratio gives the share.
    """
    rows = (
        incidents.dropna(subset=["country_numeric"])[
            ["country_numeric", "country_name", "sector"]
        ].copy()
    )
    rows["country_numeric"] = rows["country_numeric"].astype(int)
    rows["country_label"] = rows["country_name"].map(country_label)
    countries = world_countries()
    background = (
        alt.Chart(countries)
        .mark_geoshape(fill=theme.NO_DATA_COLOR, stroke="white", strokeWidth=0.4)
        .transform_filter("datum.id !== 10")
    )
    choropleth = (
        alt.Chart(rows)
        .transform_filter(sector_click)
        .transform_aggregate(
            incident_count="count()", groupby=["country_numeric", "country_label"]
        )
        .transform_joinaggregate(sector_total="sum(incident_count)")
        .transform_calculate(share="datum.incident_count / datum.sector_total")
        .transform_lookup(
            lookup="country_numeric",
            from_=alt.LookupData(countries, "id"),
            as_="geometry",
        )
        .mark_geoshape(stroke="white", strokeWidth=0.4)
        .encode(
            shape=alt.Shape("geometry:G"),
            color=alt.Color(
                "share:Q",
                title="% del sector",
                scale=theme.activity_scale(type="log"),
                legend=alt.Legend(format=".1%"),
            ),
            tooltip=[
                alt.Tooltip("country_label:N", title="País"),
                alt.Tooltip("incident_count:Q", title="Incidentes del sector", format=","),
                alt.Tooltip("share:Q", title="% del sector", format=".1%"),
                alt.Tooltip("sector_total:Q", title="Total del sector seleccionado", format=","),
            ],
        )
    )
    return (
        (background + choropleth)
        .project(type="equalEarth")
        .properties(
            width=560,
            height=280,
            title=alt.TitleParams(
                "Reparto por país de los sectores seleccionados (porcentaje)",
                subtitle="En gris, países sin incidentes del sector elegido",
                subtitleColor=theme.NEUTRAL_GRAY,
            ),
        )
    )
