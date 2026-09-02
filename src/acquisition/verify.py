"""Summary report of the raw data layer, one section per source.

Usage:
    python -m src.acquisition.verify
"""

from __future__ import annotations

import datetime
import json
import pathlib
import sys

import pandas as pd

from src.utils import config


def _null_percentages(df: pd.DataFrame, columns: list[str]) -> dict[str, float]:
    """Returns the percentage of nulls for each existing column."""
    return {
        column: round(float(df[column].isna().mean()) * 100, 1)
        for column in columns
        if column in df.columns
    }


def _summarize_nvd(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "nvd_cves.parquet"
    windows = sorted((source_dir / "windows").glob("*.parquet")) if (source_dir / "windows").exists() else []
    if not path.exists():
        if not windows:
            return None
        frames = [pd.read_parquet(window) for window in windows]
        df = pd.concat(frames, ignore_index=True)
        note = f"consolidado pendiente, {len(windows)} ventanas descargadas"
    else:
        df = pd.read_parquet(path)
        note = f"{len(windows)} ventanas en disco"
    published = pd.to_datetime(df["published"], errors="coerce", format="ISO8601")
    return {
        "records": len(df),
        "date_range": (str(published.min().date()), str(published.max().date())),
        "nulls": _null_percentages(df, ["cvss_score", "cvss_severity", "cwe_id"]),
        "note": note,
    }


def _summarize_vcdb(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "vcdb_incidents.parquet"
    if not path.exists():
        return None
    df = pd.read_parquet(path)
    years = pd.to_numeric(df["year"], errors="coerce")
    return {
        "records": len(df),
        "date_range": (str(int(years.min())), str(int(years.max()))),
        "nulls": _null_percentages(df, ["year", "victim_industry", "victim_country", "action_types"]),
    }


def _summarize_eurepoc(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "eurepoc_global_dataset_1_3.csv"
    if not path.exists():
        return None
    df = pd.read_csv(path, low_memory=False)
    date_column = next(
        (column for column in df.columns if column.strip().lower() in ("start_date", "start date")),
        None,
    )
    date_range = ("?", "?")
    if date_column is not None:
        dates = pd.to_datetime(df[date_column], errors="coerce", dayfirst=True)
        date_range = (str(dates.min().date()), str(dates.max().date()))
    key_columns = [column for column in df.columns if "receiver" in column.lower()][:3]
    return {
        "records": len(df),
        "date_range": date_range,
        "nulls": _null_percentages(df, key_columns),
        "note": f"{len(df.columns)} columnas",
    }


def _summarize_kev(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "kev_catalog.json"
    if not path.exists():
        return None
    catalog = json.loads(path.read_text(encoding="utf-8"))
    entries = catalog.get("vulnerabilities", [])
    dates = sorted(entry.get("dateAdded", "") for entry in entries if entry.get("dateAdded"))
    ransomware = sum(
        1 for entry in entries if entry.get("knownRansomwareCampaignUse", "").lower() == "known"
    )
    return {
        "records": len(entries),
        "date_range": (dates[0], dates[-1]) if dates else ("?", "?"),
        "nulls": {},
        "note": f"{ransomware} con uso conocido en ransomware",
    }


def _summarize_epss(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "epss_scores-current.csv.gz"
    if not path.exists():
        return None
    df = pd.read_csv(path, comment="#")
    return {
        "records": len(df),
        "date_range": ("snapshot", "actual"),
        "nulls": _null_percentages(df, ["epss", "percentile"]),
        "note": f"score medio {df['epss'].mean():.4f}" if "epss" in df.columns else None,
    }


def _summarize_hibp(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "breaches.json"
    if not path.exists():
        return None
    breaches = json.loads(path.read_text(encoding="utf-8"))
    dates = sorted(entry.get("BreachDate", "") for entry in breaches if entry.get("BreachDate"))
    accounts = sum(entry.get("PwnCount", 0) for entry in breaches)
    return {
        "records": len(breaches),
        "date_range": (dates[0], dates[-1]) if dates else ("?", "?"),
        "nulls": {},
        "note": f"{accounts:,} cuentas comprometidas en total",
    }


def _summarize_ransomwhere(source_dir: pathlib.Path) -> dict | None:
    path = source_dir / "payments.json"
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    addresses = payload.get("result", payload) if isinstance(payload, dict) else payload
    transactions = [
        transaction for entry in addresses for transaction in entry.get("transactions", [])
    ]
    total_usd = sum(transaction.get("amountUSD", 0) or 0 for transaction in transactions)
    times = sorted(
        transaction["time"] for transaction in transactions if transaction.get("time")
    )
    date_range = ("?", "?")
    if times:
        date_range = (
            str(datetime.date.fromtimestamp(times[0])),
            str(datetime.date.fromtimestamp(times[-1])),
        )
    return {
        "records": len(addresses),
        "date_range": date_range,
        "nulls": {},
        "note": f"{len(transactions):,} pagos, {total_usd:,.0f} USD acumulados",
    }


_SUMMARIZERS = {
    "nvd": _summarize_nvd,
    "vcdb": _summarize_vcdb,
    "eurepoc": _summarize_eurepoc,
    "kev": _summarize_kev,
    "epss": _summarize_epss,
    "hibp": _summarize_hibp,
    "ransomwhere": _summarize_ransomwhere,
}


def main() -> int:
    """Prints the raw layer summary for every known source."""
    print(f"Raw data layer: {config.DATA_RAW_DIR}\n")
    for source, summarize in _SUMMARIZERS.items():
        source_dir = config.DATA_RAW_DIR / source
        try:
            summary = summarize(source_dir)
        except Exception as error:  # noqa: BLE001 - report and keep going
            print(f"[{source:12}] ERROR al resumir: {error}")
            continue
        if summary is None:
            print(f"[{source:12}] pendiente de descarga")
            continue
        start, end = summary["date_range"]
        line = f"[{source:12}] {summary['records']:>8,} registros | rango {start} .. {end}"
        if summary.get("note"):
            line += f" | {summary['note']}"
        print(line)
        for column, percentage in summary.get("nulls", {}).items():
            print(f"{'':15}nulos {column}: {percentage}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
