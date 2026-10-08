"""Databases the converter knows about. `glot` is the sqlglot dialect used for parsing and writing SQL.

Only Oracle -> PostgreSQL has the full pipeline (custom rules, PL/SQL, risk rules, live PostgreSQL plan check). Every other
pair uses the generic pipeline: sqlglot transpile, AI for what it cannot do, and a syntax check in the target dialect."""
from __future__ import annotations

from typing import Any

DIALECTS: list[dict[str, str]] = [
    {"id": "oracle", "label": "Oracle", "glot": "oracle"},
    {"id": "postgresql", "label": "PostgreSQL", "glot": "postgres"},
    {"id": "mysql", "label": "MySQL", "glot": "mysql"},
    {"id": "mariadb", "label": "MariaDB", "glot": "mysql"},
    {"id": "sqlserver", "label": "Microsoft SQL Server", "glot": "tsql"},
    {"id": "sqlite", "label": "SQLite", "glot": "sqlite"},
    {"id": "snowflake", "label": "Snowflake", "glot": "snowflake"},
    {"id": "bigquery", "label": "Google BigQuery", "glot": "bigquery"},
    {"id": "redshift", "label": "Amazon Redshift", "glot": "redshift"},
    {"id": "databricks", "label": "Databricks SQL", "glot": "databricks"},
    {"id": "teradata", "label": "Teradata", "glot": "teradata"},
]
BY_ID = {d["id"]: d for d in DIALECTS}
FULL_PAIR = ("oracle", "postgresql")
DEFAULT_SOURCE, DEFAULT_TARGET = FULL_PAIR


def label(dialect_id: str) -> str:
    return BY_ID.get(dialect_id, {}).get("label", dialect_id)


def glot(dialect_id: str) -> str:
    return BY_ID[dialect_id]["glot"]


def is_full(src: str, tgt: str) -> bool:
    return (src, tgt) == FULL_PAIR


def validate_pair(src: str, tgt: str) -> str | None:
    """Reason the pair is not allowed, or None."""
    if src not in BY_ID or tgt not in BY_ID:
        return "Unknown database"
    if src == tgt:
        return "Choose two different databases"
    if {"mysql", "mariadb"} == {src, tgt}:
        return "MySQL and MariaDB share one SQL dialect here; pick a different pair"
    return None


def describe_pair(src: str, tgt: str) -> dict[str, Any]:
    full = is_full(src, tgt)
    return {"source": src, "target": tgt, "source_label": label(src), "target_label": label(tgt), "full": full,
            "validation": "live PostgreSQL plan check" if full else f"syntax check in the {label(tgt)} dialect (no live database)"}


def public() -> dict[str, Any]:
    return {"list": [{"id": d["id"], "label": d["label"]} for d in DIALECTS], "default_source": DEFAULT_SOURCE,
            "default_target": DEFAULT_TARGET, "full_pair": list(FULL_PAIR)}
