"""Country normalization helpers based on ISO 3166 via pycountry."""

from __future__ import annotations

import functools
import logging
import pathlib

import pandas as pd
import pycountry

logger = logging.getLogger(__name__)

# Common source spellings that pycountry's search cannot resolve.
_COUNTRY_ALIASES = {
    "russia": "RU",
    "iran": "IR",
    "south korea": "KR",
    "north korea": "KP",
    "taiwan": "TW",
    "vietnam": "VN",
    "syria": "SY",
    "venezuela": "VE",
    "bolivia": "BO",
    "moldova": "MD",
    "turkey": "TR",
    "czech republic": "CZ",
    "laos": "LA",
    "tanzania": "TZ",
    "democratic republic of congo": "CD",
    "republic of congo": "CG",
    "ivory coast": "CI",
    "palestine": "PS",
    "vatican city": "VA",
    "micronesia": "FM",
    "brunei": "BN",
    "cape verde": "CV",
    "east timor": "TL",
    "swaziland": "SZ",
    "macedonia": "MK",
    "kosovo": None,
    "unknown": None,
    "not available": None,
    "eu (region)": None,
    "nato (region)": None,
}


@functools.cache
def resolve_country(value: str | None, is_alpha_2: bool = False) -> tuple[str | None, str | None, int | None]:
    """Resolves a country name or ISO-2 code to (iso2, name, numeric).

    Args:
        value: Country name or two-letter code as found in the source.
        is_alpha_2: Whether value is already an ISO 3166-1 alpha-2 code.

    Returns:
        A tuple (alpha-2 code, English short name, numeric code), with None
        entries when the value cannot be resolved.
    """
    if value is None or not str(value).strip():
        return None, None, None
    value = str(value).strip()
    try:
        if is_alpha_2:
            country = pycountry.countries.get(alpha_2=value.upper())
        else:
            alias = _COUNTRY_ALIASES.get(value.lower(), "")
            if alias is None:
                return None, value, None
            if alias:
                country = pycountry.countries.get(alpha_2=alias)
            else:
                country = pycountry.countries.lookup(value)
    except LookupError:
        country = None
    if country is None:
        return None, value if not is_alpha_2 else None, None
    return country.alpha_2, country.name, int(country.numeric)


def add_country_codes(df: pd.DataFrame, country_column: str, is_alpha_2: bool = False) -> pd.DataFrame:
    """Adds country_iso2, country_name, and country_numeric columns.

    Args:
        df: Input DataFrame.
        country_column: Column holding country names or ISO-2 codes.
        is_alpha_2: Whether the source column contains ISO-2 codes.

    Returns:
        A copy of df with the three normalized country columns.
    """
    result = df.copy()
    resolved = result[country_column].map(lambda value: resolve_country(value, is_alpha_2))
    result["country_iso2"] = resolved.map(lambda item: item[0])
    result["country_name"] = resolved.map(lambda item: item[1])
    result["country_numeric"] = resolved.map(lambda item: item[2]).astype("Int64")
    return result


def build_country_table(destination: pathlib.Path) -> pathlib.Path:
    """Writes the ISO 3166 reference table used to join map geometries.

    Args:
        destination: Target CSV path.

    Returns:
        The destination path.
    """
    rows = [
        {"country_iso2": c.alpha_2, "country_iso3": c.alpha_3, "country_name": c.name, "country_numeric": int(c.numeric)}
        for c in pycountry.countries
    ]
    table = pd.DataFrame(rows).sort_values("country_iso2")
    destination.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(destination, index=False)
    logger.info("Country reference table written to %s (%d rows)", destination, len(table))
    return destination
