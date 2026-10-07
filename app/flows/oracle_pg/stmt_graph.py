"""Per-statement LangGraph: rules -> (Claude) -> validate -> (repair loop).

                       +--------+   residual / error   +--------+
        statement ---> | rules  | -------------------> |  llm   | <---------+
                       +--------+                      +--------+           |
                           | clean                          |               | failed, attempts left
                           v                                v               |
                       +----------------------------------------+           |
                       |               validate                 | ----------+
                       +----------------------------------------+
                                       | ok / inconclusive / skipped / out of attempts
                                       v
                                      END
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable, TypedDict

from langgraph.graph import END, StateGraph

from app.core.llm import LLM
from app.core.security import output_guard
from app.flows.oracle_pg.llm_agents import convert_with_llm
from app.flows.oracle_pg.models import Stmt
from app.flows.oracle_pg.rules import SchemaInfo, convert_rules, residual_constructs, shims_used, tokenize_placeholders
from app.flows.oracle_pg.sandbox import Sandbox

Emit = Callable[..., None]


class SState(TypedDict, total=False):
    stmt: Stmt
    last_error: str | None
    need_llm: bool
    llm_failed: bool
    done: bool


def _placeholders(sql: str) -> Counter:
    _, mapping = tokenize_placeholders(sql)
    return Counter(mapping.values())


class StmtPipeline:
    def __init__(self, *, llm: LLM, sandbox: Sandbox, schema: SchemaInfo, emit: Emit, max_repairs: int) -> None:
        self.llm, self.sandbox, self.schema, self.emit, self.max_repairs = llm, sandbox, schema, emit, max_repairs
        g = StateGraph(SState)
        g.add_node("rules", self.n_rules)
        g.add_node("llm", self.n_llm)
        g.add_node("validate", self.n_validate)
        g.set_entry_point("rules")
        g.add_conditional_edges("rules", self.r_after_rules, {"llm": "llm", "validate": "validate", "end": END})
        g.add_conditional_edges("llm", self.r_after_llm, {"validate": "validate", "end": END})
        g.add_conditional_edges("validate", self.r_after_validate, {"llm": "llm", "end": END})
        self.graph = g.compile()

    def run(self, stmt: Stmt) -> Stmt:
        try:
            self.graph.invoke({"stmt": stmt, "last_error": None})
        except Exception as exc:  # one bad statement must never kill the run
            stmt.validation = {"status": "failed", "mode": self.sandbox.mode, "error": f"internal error: {type(exc).__name__}"}
            stmt.notes.append(f"pipeline error: {str(exc)[:160]}")
        return stmt

    # ---------------------------------------------------------------- nodes
    def n_rules(self, state: SState) -> SState:
        s = state["stmt"]
        if s.kind == "jpql":
            s.pg_sql, s.method, s.status = s.oracle_sql, "passthrough", "portable"
            s.validation = {"status": "skipped", "mode": "n/a", "error": None}
            s.notes.append("JPQL/HQL is database-independent: no SQL change needed. Check the Hibernate dialect setting.")
            self.emit("Converter", f"{s.id} {s.label}: JPQL, portable as-is", "info", id=s.id)
            return {"need_llm": False, "done": True}
        r = convert_rules(s, self.schema)
        s.notes += r.notes
        s.warnings = r.warnings
        s.shims = r.shims
        s.meta["flags"] = r.flags
        if r.error:
            s.residual = [r.error]
            s.pg_sql = None
            need = True
        else:
            s.pg_sql, s.method, s.residual = r.pg_sql, "rules", r.residual
            need = bool(r.residual)
        if s.kind == "plsql":
            need = True
        if need:
            self.emit("Converter", f"{s.id} {s.label}: rules engine could not finish ({'; '.join(s.residual) or 'PL/SQL'})",
                      "warn", id=s.id)
        else:
            self.emit("Converter", f"{s.id} {s.label}: converted by rules ({len(s.notes)} rewrite{'s' if len(s.notes) != 1 else ''})",
                      "info", id=s.id)
        return {"need_llm": need}

    def r_after_rules(self, state: SState) -> str:
        if state.get("done"):
            return "end"
        s = state["stmt"]
        if state.get("need_llm"):
            if self.llm.available:
                return "llm"
            if s.pg_sql is None:
                s.validation = {"status": "skipped", "mode": self.sandbox.mode,
                                "error": "needs the LLM converter, which is not configured (set ANTHROPIC_API_KEY)"}
                return "end"
        return "validate"

    def n_llm(self, state: SState) -> SState:
        s = state["stmt"]
        s.attempts += 1
        self.emit("Converter", f"{s.id} {s.label}: asking Claude (attempt {s.attempts})", "info", id=s.id)
        res = convert_with_llm(self.llm, s, self.schema, state.get("last_error"))
        if not res or not str(res.get("postgres_sql", "")).strip():
            s.notes.append(f"LLM call failed: {self.llm.last_error or 'empty answer'}")
            if s.pg_sql is None:
                s.validation = {"status": "failed", "mode": self.sandbox.mode, "error": "LLM call failed"}
            return {"llm_failed": True}
        sql = str(res["postgres_sql"]).strip().rstrip(";") if s.kind != "plsql" else str(res["postgres_sql"]).strip()
        reason = output_guard(sql)
        if reason:
            s.notes.append(reason)
            s.validation = {"status": "failed", "mode": self.sandbox.mode, "error": reason}
            return {"llm_failed": True}
        s.pg_sql = sql
        s.method = "llm" if s.kind == "plsql" or s.method == "none" else "rules+llm"
        s.llm_explanation = str(res.get("explanation", ""))[:800]
        if res.get("needs_manual_review"):
            s.meta["llm_manual_review"] = str(res.get("manual_review_reason", "model asked for manual review"))[:300]
        for a in (res.get("assumptions") or [])[:4]:
            s.notes.append(f"assumption: {str(a)[:200]}")
        if s.kind == "plsql":
            s.residual = []
        else:
            s.residual = residual_constructs(sql, s.oracle_sql, parser_output=False)
            if _placeholders(s.oracle_sql) != _placeholders(sql):
                s.residual.append("bind parameters differ from the original statement")
            s.shims = shims_used(sql)
        return {"llm_failed": False}

    def r_after_llm(self, state: SState) -> str:
        return "end" if state.get("llm_failed") else "validate"

    def n_validate(self, state: SState) -> SState:
        s = state["stmt"]
        mode = self.sandbox.mode
        if s.kind not in ("plsql",) and s.residual:
            err = "Oracle-only constructs remain: " + "; ".join(s.residual)
            s.validation = {"status": "failed", "mode": mode, "error": err}
        elif s.kind == "plsql":
            status, err, created = self.sandbox.validate_plpgsql(s.pg_sql or "")
            if status in ("ok", "skipped"):
                self.sandbox.known_calls.update(created)
            s.validation = {"status": status, "mode": mode, "error": err}
        elif s.kind == "ddl":
            ok, err = self.sandbox.apply_ddl(s.pg_sql or "")
            s.validation = {"status": "ok" if ok else "failed", "mode": mode, "error": err}
        else:
            status, err = self.sandbox.validate_query(s.pg_sql or "")
            s.validation = {"status": status, "mode": mode, "error": err}
        v = s.validation["status"]
        lvl = "ok" if v == "ok" else ("warn" if v in ("inconclusive", "skipped") else "error")
        txt = {"ok": "valid on PostgreSQL" if mode == "postgres" else "valid syntax (no live PostgreSQL)",
               "inconclusive": "parses; bind-parameter types need a cast", "skipped": "not planned",
               "failed": "failed"}[v]
        err_txt = f" - {s.validation['error']}" if s.validation["error"] else ""
        self.emit("Validator", f"{s.id} {s.label}: {txt}{err_txt}"[:300], lvl, id=s.id)
        return {"last_error": s.validation["error"]}

    def r_after_validate(self, state: SState) -> str:
        s = state["stmt"]
        if s.validation["status"] != "failed" or s.kind == "jdbc_call":
            return "end"
        if state.get("llm_failed") or not self.llm.available:
            return "end"
        if s.attempts >= 1 + self.max_repairs:
            return "end"
        return "llm"
