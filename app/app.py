"""Streamlit front for the cyberattacks and vulnerabilities dashboard.

Run from the project root:
    streamlit run app/app.py

Design justifications for every chart live in the EDA notebook, not here;
the dashboard itself stays clean for exploration.
"""

from __future__ import annotations

import pathlib
import sys
from collections.abc import Callable

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import altair as alt
import pandas as pd
import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from src.utils import config
from src.visualization import charts
from src.visualization.theme import (
    SEVERITY_LABELS,
    SEVERITY_ORDER,
    localize,
    register_theme,
)

st.set_page_config(
    page_title="Panorama global de ciberataques 2015-2025",
    page_icon="🛡️",
    layout="wide",
)

# No native option exists for the top padding; 2.5rem keeps the title clear
# of the toolbar while dropping most of the default blank band.
st.markdown(
    "<style>.block-container { padding-top: 2.5rem; }</style>",
    unsafe_allow_html=True,
)

# Streamlit does not rerun the script when the theme changes in its settings
# menu, so st.context.theme still reports the previous variant and the charts
# keep a palette built for the other background (streamlit/streamlit#11920).
# This probe reads the background colour Streamlit hands to every component,
# which does follow the menu, and publishes it back so the run that redraws
# the charts knows which variant they are sitting on.
_THEME_PROBE_JS = r"""
export default function (component) {
  const { parentElement, setStateValue } = component

  const readVariant = () => {
    const raw = getComputedStyle(parentElement)
      .getPropertyValue("--st-background-color")
      .trim()
    if (!raw) return null
    // Resolving through a span normalises hex, rgb() and named colours alike.
    const probe = document.createElement("span")
    probe.style.color = raw
    parentElement.appendChild(probe)
    const channels = getComputedStyle(probe).color.match(/[\d.]+/g)
    probe.remove()
    if (!channels || channels.length < 3) return null
    const [r, g, b] = channels.slice(0, 3).map(Number)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b < 128 ? "dark" : "light"
  }

  let published = null
  const publish = () => {
    const variant = readVariant()
    if (variant && variant !== published) {
      published = variant
      setStateValue("variant", variant)
    }
  }

  publish()
  const timer = setInterval(publish, 400)
  return () => clearInterval(timer)
}
"""

_theme_probe = st.components.v2.component(
    "theme_probe",
    html="<span></span>",
    css=":host { display: block; height: 0; }",
    js=_THEME_PROBE_JS,
)


def active_theme_is_dark() -> bool:
    """Reports whether the viewer has the dark variant active.

    Mounts the probe and trusts what it reports. Its first answer arrives on
    the rerun after mounting, so until then the value Streamlit itself
    reports stands in, which is right on every load that does not follow a
    theme change.

    Returns:
        True for the dark variant, the default while nothing is known yet.
    """
    with st.sidebar:
        probe = _theme_probe(key="theme_probe", on_variant_change=lambda: None)
    if probe.variant in ("dark", "light"):
        return probe.variant == "dark"
    theme_info = getattr(st.context, "theme", None)
    return (getattr(theme_info, "type", None) or "dark") == "dark"


@st.cache_data
def load_datasets() -> dict[str, pd.DataFrame]:
    """Loads every processed dataset once per session."""
    processed = config.DATA_PROCESSED_DIR
    return {
        "vulnerabilities": pd.read_parquet(processed / "vulnerabilities.parquet"),
        "monthly": pd.read_parquet(processed / "vulnerabilities_monthly.parquet"),
        "incidents": pd.read_parquet(processed / "incidents.parquet"),
        "breaches": pd.read_parquet(processed / "breaches.parquet"),
        "payments": pd.read_parquet(processed / "ransomware_payments.parquet"),
    }


def render_chart(
    builder: Callable[..., alt.TopLevelMixin],
    df: pd.DataFrame,
    height: int | None = None,
    stretch: bool = True,
    **kwargs,
) -> None:
    """Renders a chart, degrading gracefully on empty selections.

    Args:
        builder: Chart constructor from src.visualization.charts.
        df: Analysis-ready frame for the builder.
        height: Overrides the builder height so charts sharing a row line
            up; their baselines and plot areas must match to be comparable.
        stretch: Let the chart fill the column, and grow with the fullscreen
            button. Maps included: the autosize Streamlit injects rescales
            the projection correctly.
        **kwargs: Extra arguments forwarded to the builder.
    """
    if df.empty:
        st.info("Sin datos para los filtros seleccionados.")
        return
    chart = builder(df, **kwargs)
    # Vega-Lite takes no height on a concatenation; those size their own panels.
    if height is not None and not isinstance(chart, (alt.HConcatChart, alt.VConcatChart)):
        chart = chart.properties(height=height)
    st.altair_chart(localize(chart), width="stretch" if stretch else "content")


def render_selectable(chart: alt.Chart, key: str, mode: str) -> list:
    """Renders a chart that publishes its selection back to Python.

    Vega-Lite cannot resize concatenated specs, so the linked views are not
    concatenated here: each one is its own single-view spec inside a
    Streamlit column, which lets both stretch with the window. The link is
    made server-side instead, with the selection returned by on_select.

    Args:
        chart: Chart carrying exactly one named selection parameter.
        key: Widget key holding the selection state.
        mode: Name of that selection parameter.

    Returns:
        The selected values, empty when nothing is selected (meaning all).
    """
    event = st.altair_chart(
        localize(chart), width="stretch", on_select="rerun", selection_mode=mode, key=key
    )
    return event.selection.get(mode, []) if event and event.selection else []


def selected_values(selection: list, field: str) -> list:
    """Pulls one field out of a selection payload, whatever its shape."""
    if isinstance(selection, dict):
        values = selection.get(field, [])
        return list(values) if isinstance(values, list) else [values]
    return [row[field] for row in selection if isinstance(row, dict) and field in row]


@st.dialog("Datos de la sección", width="large")
def show_table(frame: pd.DataFrame) -> None:
    """Opens the figures behind the charts in a modal."""
    st.dataframe(frame, width="stretch")


def data_table(label: str, frame: pd.DataFrame, key: str) -> None:
    """Offers the figures behind the charts as a table.

    Several accent colors of the palette sit below the 3:1 contrast ratio
    against the light surface, and the relief the design system prescribes
    for that case is an accessible reading of the same numbers. A modal
    rather than an expander, so opening it never reflows the charts above.

    Args:
        label: Text of the button that opens the modal.
        frame: Table to show; nothing is rendered when it is empty.
        key: Widget key, unique per section.
    """
    if frame.empty:
        return
    if st.button(label, key=key, icon=":material/table_view:"):
        show_table(frame)


# Taller than in print: on screen the title and legend sit outside the plot.
ROW_TALL = 520
ROW_MID = 400
ROW_SHORT = 380

data = load_datasets()

# --- sidebar
ALL_SOURCES = ["VCDB", "EuRepoC"]
FILTER_KEYS = ("f_years", "f_severities", "f_sources", "f_sectors")


def reset_filters() -> None:
    """Drops the filter state so every widget falls back to its default."""
    for key in FILTER_KEYS:
        st.session_state.pop(key, None)


# Before any chart is built, while the palette is still being resolved.
register_theme(dark=active_theme_is_dark())

st.sidebar.title("Filtros")
year_range = st.sidebar.slider(
    "Periodo",
    min_value=config.ANALYSIS_START_YEAR,
    max_value=config.ANALYSIS_END_YEAR,
    value=(config.ANALYSIS_START_YEAR, config.ANALYSIS_END_YEAR),
    key="f_years",
)
# Displays the Spanish reading; translating the option breaks the filter.
severities = st.sidebar.multiselect(
    "Severidad CVSS",
    SEVERITY_ORDER,
    default=SEVERITY_ORDER,
    format_func=lambda band: SEVERITY_LABELS[band],
    key="f_severities",
)
sources = st.sidebar.multiselect(
    "Fuente de incidentes", ALL_SOURCES, default=ALL_SOURCES, key="f_sources"
)
all_sectors = sorted(data["incidents"]["sector"].unique())
sectors = st.sidebar.multiselect("Sectores", all_sectors, default=all_sectors, key="f_sectors")

st.sidebar.button("Restablecer filtros", on_click=reset_filters, width="stretch")


def filter_all(start: int, end: int) -> dict[str, pd.DataFrame]:
    """Applies the sidebar filters over a given year window.

    Args:
        start: First year kept, read by the queries as the @start local.
        end: Last year kept, read by the queries as the @end local.

    Returns:
        One filtered frame per dataset, keyed as in load_datasets.
    """
    return {
        "vulnerabilities": data["vulnerabilities"].query(
            "@start <= year <= @end and cvss_severity in @severities"
        ),
        "monthly": data["monthly"].query(
            "@start <= year <= @end and cvss_severity in @severities"
        ),
        "incidents": data["incidents"].query(
            "@start <= year <= @end and source in @sources and sector in @sectors"
        ),
        "breaches": data["breaches"].query("@start <= year <= @end and sector in @sectors"),
        "payments": data["payments"].query("@start <= year <= @end"),
    }


start_year, end_year = year_range
current = filter_all(start_year, end_year)

# Ransomwhere answers only to the period, and the KPI label says so.
payments_in_step = (
    len(severities) == len(SEVERITY_ORDER)
    and len(sources) == len(ALL_SOURCES)
    and len(sectors) == len(all_sectors)
)

# Halves of equal length, since a preceding window exists only for subranges.
half_span = (end_year - start_year + 1) // 2
if half_span >= 1:
    first_half = filter_all(start_year, start_year + half_span - 1)
    second_half = filter_all(end_year - half_span + 1, end_year)
else:
    first_half = second_half = None


def es_number(value: float, decimals: int = 0) -> str:
    """Formats a number with the Spanish thousands and decimal separators.

    Python groups with commas and points the decimal, which is the English
    convention and clashes with the charts.

    Args:
        value: The figure to render.
        decimals: Digits after the separator.

    Returns:
        The number as text, grouped in thousands.
    """
    return f"{value:,.{decimals}f}".translate(str.maketrans({",": ".", ".": ","}))


def metric_with_delta(
    column: DeltaGenerator,
    label: str,
    value: float,
    series_key: str,
    measure: Callable[[pd.DataFrame], float],
    fmt: Callable[[float], str],
    help_text: str | None = None,
    show_delta: bool = True,
) -> None:
    """Renders a KPI with the trend between both halves of the period.

    Args:
        column: Layout column the indicator is drawn into.
        label: Caption above the figure.
        value: Figure for the whole selected period.
        series_key: Dataset the measure reads, as keyed by load_datasets.
        measure: Reduces one filtered frame to the scalar being tracked.
        fmt: Renders that scalar for display.
        help_text: Scope note for indicators the sidebar filters cannot reach
            in full, so the reader is never left to assume a figure responds
            to a filter it does not.
        show_delta: Suppresses the trend when the active filters leave this
            indicator answering a narrower question than the rest of the row.
            A percentage next to neighbours reading zero invites a comparison
            that does not hold, and a note the reader has to hover to find
            does not undo what the row already showed.
    """
    delta = None
    if show_delta and first_half is not None:
        before = measure(first_half[series_key])
        after = measure(second_half[series_key])
        if before > 0:
            delta = f"{(after - before) / before * 100:+.0f}%"
    column.metric(label, fmt(value), delta=delta, help=help_text)


# --- header
st.title("Panorama global de ciberataques y vulnerabilidades")

kpis = st.columns(6)


def critical_share_of(frame: pd.DataFrame) -> float:
    """Share of critical CVEs, in percentage points."""
    return (frame["cvss_severity"] == "CRITICAL").mean() * 100 if len(frame) else 0.0


critical_share = critical_share_of(current["vulnerabilities"])
metric_with_delta(
    kpis[0], "CVEs publicadas", len(current["vulnerabilities"]),
    "vulnerabilities", len, es_number,
)
share_delta = None
if first_half is not None:
    share_delta = critical_share_of(second_half["vulnerabilities"]) - critical_share_of(
        first_half["vulnerabilities"]
    )
kpis[1].metric(
    "% críticas",
    f"{es_number(critical_share, 1)} %",
    delta=(
        f"{share_delta:+.1f} pp".replace(".", ",")
        if share_delta is not None
        else None
    ),
)
metric_with_delta(
    kpis[2], "Explotadas (KEV)", int(current["vulnerabilities"]["is_kev"].sum()),
    "vulnerabilities", lambda f: int(f["is_kev"].sum()), es_number,
)
metric_with_delta(
    kpis[3], "Incidentes", len(current["incidents"]),
    "incidents", len, es_number,
    help_text="La serie mide esfuerzo de documentación, no incidencia. VCDB decae "
              "tras 2020 y EuRepoC termina en diciembre de 2024, así que la "
              "variación entre periodos refleja sobre todo cómo recogen las fuentes.",
)
metric_with_delta(
    kpis[4], "Cuentas expuestas", current["breaches"]["pwn_count"].sum(),
    "breaches", lambda f: f["pwn_count"].sum(), lambda v: f"{es_number(v / 1e6)} M",
)
metric_with_delta(
    kpis[5],
    "Ransomware (USD)" if payments_in_step else "Ransomware (USD) · solo periodo",
    current["payments"]["amount_usd"].sum(),
    "payments",
    lambda f: f["amount_usd"].sum(),
    lambda v: f"{es_number(v / 1e6)} M",
    help_text="Ransomwhere solo registra fecha e importe, así que este indicador "
              "responde al periodo pero no al sector, la fuente ni la severidad.",
    show_delta=payments_in_step,
)
if first_half is not None:
    st.caption(
        f"Δ segunda mitad del periodo ({end_year - half_span + 1}-{end_year}) frente a la "
        f"primera ({start_year}-{start_year + half_span - 1})."
    )

st.divider()

# --- section 1, the threat grows
st.header(
    "La amenaza crece",
    help="Arrastra un rango de años sobre el área para acotar la "
         "estacionalidad; sin selección se muestran todos.",
)
st.markdown(
    "Cuántas vulnerabilidades se publican, en qué meses del año y con qué gravedad.",
    help="2015 no es comparable con el resto porque casi todas sus CVEs "
         "puntúan en CVSS v2, una escala que da valores más bajos que la v3 "
         "usada desde 2016. El ritmo mensual sigue la capacidad de análisis "
         "del NVD, no un patrón estacional del atacante.",
)
col_left, col_right = st.columns(2)
with col_left:
    year_brush = alt.selection_interval(name="years", encodings=["x"])
    temporal = (
        charts.build_temporal_evolution_chart(current["monthly"])
        .add_params(year_brush)
        .properties(height=ROW_MID)
    )
    picked_years = selected_values(render_selectable(temporal, "sel_years", "years"), "year")
seasonal = current["monthly"]
if picked_years:
    # A brush reports either every selected year or just the two ends.
    span = [int(year) for year in picked_years]
    seasonal = seasonal[seasonal["year"].between(min(span), max(span))]
with col_right:
    render_chart(charts.build_seasonality_chart, seasonal, height=ROW_MID)
render_chart(charts.build_severity_share_chart, current["monthly"])
data_table(
    "Ver los datos de esta sección",
    current["monthly"].pivot_table(index="year", columns="cvss_severity",
                                   values="cve_count", aggfunc="sum", observed=True).fillna(0).astype(int),
    key="tabla_amenaza",
)

st.divider()

# --- section 2, where it lands and on whom
st.header(
    "Dónde golpea y a quién",
    help="Haz clic en una celda del mapa de calor (mayús+clic para varias) "
         "para acotar el mapa a ese sector; sin selección el mapa reparte "
         "todos los incidentes.",
)
st.markdown(
    "Qué sector sufre cada tipo de ataque, en qué países y a manos de quién.",
    help="La celda mayor, Educación y ciencia con hacking, está inflada por "
         "la campaña MOVEit de 2023, que VCDB registra como un incidente por "
         "víctima (612 de sus 694), y un evento masivo así puede reordenar el "
         "perfil sectorial de un año entero. La banda sin atribuir crece "
         "desde 2022 porque EuRepoC amplió su recogida, no porque la "
         "atribución empeore. Las comparaciones entre países reflejan "
         "actividad documentada, no incidencia real.",
)
col_left, col_right = st.columns(2)
with col_left:
    sector_click = alt.selection_point(name="sector", fields=["sector"], toggle="true")
    heatmap = charts.build_sector_attack_heatmap(
        current["incidents"], selection=sector_click
    ).properties(height=ROW_MID)
    picked_sectors = selected_values(
        render_selectable(heatmap, "sel_sector", "sector"), "sector"
    )
geo = current["incidents"]
if picked_sectors:
    geo = geo[geo["sector"].isin(picked_sectors)]
with col_right:
    render_chart(
        charts.build_geographic_risk_chart, geo, height=ROW_MID, as_share=True
    )
col_left, col_right = st.columns(2)
with col_left:
    render_chart(charts.build_top_countries_chart, current["incidents"], height=ROW_TALL)
with col_right:
    render_chart(charts.build_actor_type_chart, current["incidents"], height=ROW_TALL)
data_table(
    "Ver los datos de esta sección",
    current["incidents"].pivot_table(index="sector", columns="attack_category",
                                     values="incident_id", aggfunc="count").fillna(0).astype(int),
    key="tabla_geografia",
)

st.divider()

# --- section 3, what fails and what to prioritise
st.header(
    "Qué falla y qué priorizar",
    help="Haz clic en una debilidad para ver dónde caen sus CVEs en el plano "
         "de gravedad y explotabilidad; sin selección, el plano las muestra "
         "todas.",
)
st.markdown(
    "Qué debilidades fallan más y cuáles cruzan gravedad alta con explotación probable.",
    help="El EPSS estima la probabilidad de que una CVE se explote en los "
         "treinta días siguientes y es una instantánea actual, no una serie "
         "histórica. El catálogo KEV solo recoge explotación confirmada desde "
         "finales de 2021, así que los años anteriores salen "
         "infrarrepresentados.",
)
col_left, col_right = st.columns(2)
with col_left:
    cwe_click = alt.selection_point(name="cwe", fields=["cwe_id"], toggle="true")
    cwe_chart = charts.build_cwe_distribution_chart(
        current["vulnerabilities"], selection=cwe_click
    ).properties(height=ROW_TALL)
    picked_cwes = selected_values(render_selectable(cwe_chart, "sel_cwe", "cwe"), "cwe_id")
plane = current["vulnerabilities"]
if picked_cwes:
    plane = plane[plane["cwe_id"].isin(picked_cwes)]
with col_right:
    render_chart(charts.build_cvss_epss_chart, plane, height=ROW_TALL)
data_table(
    "Ver los datos de esta sección",
    current["vulnerabilities"][current["vulnerabilities"]["cwe_id"] != "Unknown"]
    .groupby("cwe_id")
    .agg(CVEs=("cve_id", "count"), CVSS_medio=("cvss_score", "mean"),
         EPSS_medio=("epss_score", "mean"), Explotadas=("is_kev", "sum"))
    .nlargest(20, "CVEs")
    .round(3),
    key="tabla_debilidades",
)

st.divider()

# --- section 4, the cost
st.header("El coste")
st.markdown(
    "Cuentas expuestas en brechas y dinero pagado en rescates de ransomware.",
    help="El sector de cada brecha se infiere del texto libre que publica "
         "HIBP. Ransomwhere solo contabiliza los pagos verificables en cadena "
         "de bloques y su cobertura termina a mediados de 2024, así que la "
         "caída posterior mezcla el fenómeno con el límite del método.",
)
col_left, col_right = st.columns(2)
with col_left:
    render_chart(charts.build_breach_sector_chart, current["breaches"], height=ROW_MID)
with col_right:
    render_chart(
        charts.build_breach_year_chart, current["breaches"], height=ROW_MID,
        axis_title="Cuentas expuestas (millones)",
    )
col_left, col_right = st.columns(2)
with col_left:
    render_chart(charts.build_ransomware_payments_chart, current["payments"], height=ROW_SHORT)
with col_right:
    render_chart(charts.build_ransomware_families_chart, current["payments"], height=ROW_SHORT)
data_table(
    "Ver los datos de esta sección",
    current["breaches"].groupby(["year", "sector"])
    .agg(Brechas=("name", "count"), Cuentas_M=("pwn_count", lambda s: round(s.sum() / 1e6, 1)))
    .reset_index(),
    key="tabla_coste",
)

# --- footer
st.divider()
st.subheader("Fuentes de datos")
with st.expander("Ver la procedencia y la cobertura de cada fuente"):
    st.markdown(
        """
| Fuente | Contenido | Cobertura |
|---|---|---|
| NVD/NIST | Vulnerabilidades (CVE, CVSS, CWE) | 2015-2025 |
| VCDB (Verizon) | Incidentes reales VERIS | Sesgo EE. UU., decae tras 2020 |
| EuRepoC | Incidentes con atribución | Hasta diciembre de 2024 |
| CISA KEV | Explotación confirmada | Catálogo desde finales de 2021 |
| EPSS (FIRST.org) | Probabilidad de explotación | Instantánea actual |
| Have I Been Pwned | Brechas y cuentas expuestas | Sector inferido |
| Ransomwhere | Pagos de ransomware verificados | 2012-2024 |

Las comparaciones entre países reflejan actividad documentada, no
incidencia real.
        """
    )
st.caption(
    "Caso práctico de Visualización de Datos · Máster en Ingeniería y "
    "Ciencia de Datos (UNED) · Olaya Folgueiras González"
)
