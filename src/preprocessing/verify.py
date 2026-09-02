"""Summary report of the processed data layer.

Usage:
    python -m src.preprocessing.verify
"""

from __future__ import annotations

import pathlib
import sys

import pandas as pd

from src.utils import config


def _print_distribution(df: pd.DataFrame, column: str, top: int = 6) -> None:
    counts = df[column].value_counts(dropna=False).head(top)
    total = len(df)
    for value, count in counts.items():
        print(f"{'':15}{column}={value}: {count:,} ({count / total * 100:.1f}%)")


def _summarize_vulnerabilities(path: pathlib.Path) -> None:
    df = pd.read_parquet(path)
    print(
        f"[vulnerabilities      ] {len(df):>8,} filas | {df['year'].min()}-{df['year'].max()}"
        f" | imputadas CVSS {df['cvss_imputed'].mean() * 100:.1f}%"
        f" | KEV {int(df['is_kev'].sum()):,} | EPSS cobertura {df['epss_score'].notna().mean() * 100:.1f}%"
    )
    _print_distribution(df, "cvss_severity")


def _summarize_incidents(path: pathlib.Path) -> None:
    df = pd.read_parquet(path)
    print(
        f"[incidents            ] {len(df):>8,} filas | {df['year'].min()}-{df['year'].max()}"
        f" | país resuelto {df['country_iso2'].notna().mean() * 100:.1f}%"
    )
    _print_distribution(df, "source", top=3)
    _print_distribution(df, "sector")
    _print_distribution(df, "attack_category")


def _summarize_breaches(path: pathlib.Path) -> None:
    df = pd.read_parquet(path)
    print(
        f"[breaches             ] {len(df):>8,} filas | {df['year'].min()}-{df['year'].max()}"
        f" | cuentas {df['pwn_count'].sum():,}"
    )
    _print_distribution(df, "sector")


def _summarize_payments(path: pathlib.Path) -> None:
    df = pd.read_parquet(path)
    print(
        f"[ransomware_payments  ] {len(df):>8,} filas | {df['year'].min()}-{df['year'].max()}"
        f" | {df['amount_usd'].sum():,.0f} USD"
    )
    _print_distribution(df, "family", top=5)


def _summarize_monthly(path: pathlib.Path) -> None:
    df = pd.read_parquet(path)
    print(f"[vulnerabilities_monthly] {len(df):>6,} filas agregadas (año×mes×severidad×kev)")


_SUMMARIZERS = {
    "vulnerabilities.parquet": _summarize_vulnerabilities,
    "vulnerabilities_monthly.parquet": _summarize_monthly,
    "incidents.parquet": _summarize_incidents,
    "breaches.parquet": _summarize_breaches,
    "ransomware_payments.parquet": _summarize_payments,
}


def main() -> int:
    """Prints the processed layer summary for every expected dataset."""
    print(f"Processed data layer: {config.DATA_PROCESSED_DIR}\n")
    for filename, summarize in _SUMMARIZERS.items():
        path = config.DATA_PROCESSED_DIR / filename
        if not path.exists():
            print(f"[{filename}] pendiente")
            continue
        try:
            summarize(path)
        except Exception as error:  # noqa: BLE001 - report and keep going
            print(f"[{filename}] ERROR: {error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
