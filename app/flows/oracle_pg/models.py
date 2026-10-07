"""Shared data model for the Oracle -> PostgreSQL flows."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Risk:
    category: str
    severity: str  # high | medium | low
    message: str
    suggestion: str = ""
    source: str = "rule"  # rule | llm


@dataclass
class Stmt:
    id: str
    kind: str  # jdbc | jdbc_call | mybatis | jpa_native | jpql | sql | ddl | plsql
    file: str
    line: int
    label: str
    oracle_sql: str
    constructs: list[str] = field(default_factory=list)
    weight: int = 0
    tier: str = "trivial"  # trivial | moderate | hard
    dynamic: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    # --- results, filled in by the agents ---
    pg_sql: str | None = None
    method: str = "none"  # rules | llm | rules+llm | passthrough | none
    notes: list[str] = field(default_factory=list)
    residual: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    shims: list[str] = field(default_factory=list)
    attempts: int = 0
    validation: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "mode": "", "error": None})
    risks: list[Risk] = field(default_factory=list)
    llm_explanation: str = ""
    confidence: float = 0.0
    status: str = "pending"  # auto | review | manual | portable
    effort_min: int = 0
    baseline_min: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


TIER_BASELINE_MIN = {"trivial": 15, "moderate": 45, "hard": 120}
PLSQL_BASELINE_MIN = 180
