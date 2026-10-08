"""Orchestrator helpers: build the inventory the Orchestrator agent reasons about, and turn its answers into a *validated*
plan. The model proposes; this code disposes: every field is clamped, and validation/safety steps cannot be switched off."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from app.config import settings
from app.core.security import Finding
from app.flows.oracle_pg.models import Stmt

REVIEW_DEPTHS = ("all", "non_trivial", "rules_only")


@dataclass
class Plan:
    run_code_reader: bool = True
    review_depth: str = "non_trivial"
    run_critic: bool = True
    max_repairs: int = 2
    focus: list[str] = field(default_factory=list)
    rationale: str = "Default plan: read unassembled SQL, review non-trivial statements, and let the Critic retry failures."
    source: str = "default"  # default | orchestrator

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_inventory(stmts: list[Stmt], findings: list[Finding], stats: dict, llm_available: bool) -> dict[str, Any]:
    constructs: Counter[str] = Counter(c for s in stmts for c in s.constructs)
    reader = stats.get("reader", {})
    prof = stats.get("profile", {})
    return {
        "statements": len(stmts),
        "by_kind": dict(Counter(s.kind for s in stmts)),
        "by_difficulty": dict(Counter(s.tier for s in stmts)),
        "plsql_units": sum(1 for s in stmts if s.kind == "plsql"),
        "top_oracle_constructs": dict(constructs.most_common(10)),
        "dynamic_sql_statements": sum(1 for s in stmts if s.dynamic),
        "unassembled_sql_fragments": reader.get("gap_fragments", 0),
        "frameworks": [f["name"] for f in prof.get("frameworks", [])],
        "findings": dict(Counter(f.category for f in findings).most_common(8)),
        "claude_available": llm_available,
        "limits": {"max_repairs_allowed": settings.max_repair_attempts},
    }


def default_plan(inventory: dict[str, Any]) -> Plan:
    p = Plan()
    p.run_code_reader = inventory.get("unassembled_sql_fragments", 0) > 0
    p.run_critic = bool(inventory.get("claude_available"))
    p.max_repairs = settings.max_repair_attempts
    return p


def sanitize_plan(raw: dict[str, Any] | None, inventory: dict[str, Any]) -> Plan:
    """Clamp the model's answer. Anything missing or invalid falls back to the default for that field."""
    base = default_plan(inventory)
    if not isinstance(raw, dict):
        return base
    plan = Plan(source="orchestrator")
    plan.run_code_reader = bool(raw.get("run_code_reader", base.run_code_reader)) and inventory.get("unassembled_sql_fragments", 0) > 0
    depth = raw.get("review_depth")
    plan.review_depth = depth if depth in REVIEW_DEPTHS else base.review_depth
    plan.run_critic = bool(raw.get("run_critic", base.run_critic)) and bool(inventory.get("claude_available"))
    try:
        plan.max_repairs = max(0, min(int(raw.get("max_repairs", base.max_repairs)), settings.max_repair_attempts))
    except (TypeError, ValueError):
        plan.max_repairs = base.max_repairs
    plan.focus = [str(f).strip()[:90] for f in (raw.get("focus") or []) if str(f).strip()][:4]
    plan.rationale = str(raw.get("rationale") or "").strip()[:500] or base.rationale
    return plan


def failing_statements(stmts: list[Stmt]) -> list[Stmt]:
    return [s for s in stmts if s.validation.get("status") == "failed" or (s.status == "manual" and s.kind != "jpql")]


def triage_payload(failing: list[Stmt]) -> list[dict[str, Any]]:
    return [{"id": s.id, "label": s.label, "kind": s.kind, "tier": s.tier, "attempts": s.attempts,
             "oracle_constructs": s.constructs[:6], "error": (s.validation.get("error") or "")[:240]} for s in failing[:30]]
