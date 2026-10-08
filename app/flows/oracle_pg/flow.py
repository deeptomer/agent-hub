"""Flow 1: Oracle -> PostgreSQL migration of a SQL-heavy Java application (outer LangGraph),
and Flow 2: single Oracle SQL / PL/SQL snippet converter (same agents, one statement)."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from app.config import settings
from app.core import dialects
from app.core.registry import FlowDef, RunContext, register
from app.core.security import Finding, UnsafeInput, fetch_github_zip, safe_extract_zip
from app.flows.oracle_pg import extract, reader
from app.flows.oracle_pg.constructs import detect, tier_for
from app.flows.oracle_pg.llm_agents import critique_with_llm, plan_with_llm, review_with_llm, summarise_with_llm, triage_with_llm
from app.flows.oracle_pg.models import Stmt
from app.flows.oracle_pg.orchestrator import Plan
from app.flows.oracle_pg.report import build_report
from app.flows.oracle_pg.risk import assess, finalize, merge_risks
from app.flows.oracle_pg.rules import SchemaInfo, schema_from_ddl
from app.flows.oracle_pg.sandbox import Sandbox
from app.flows.oracle_pg.generic import GenericPipeline, review_generic
from app.flows.oracle_pg.stmt_graph import StmtPipeline


class FlowState(TypedDict, total=False):
    root: Path
    source_name: str
    stmts: list[Stmt]
    findings: list[Finding]
    stats: dict
    schema: SchemaInfo
    pipeline: StmtPipeline
    report: dict
    plan: Plan
    done: list[str]
    next: str


def _order_ddl(ddl: list[Stmt]) -> list[Stmt]:
    """Sequences first, then tables in foreign-key dependency order, then indexes/views."""
    def name(s: Stmt) -> str:
        m = re.match(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:UNIQUE\s+)?\w+\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)", s.oracle_sql, re.I)
        return (m.group(1) if m else s.label).lower().strip('"')

    seqs = [s for s in ddl if re.match(r"^\s*CREATE\s+SEQUENCE", s.oracle_sql, re.I)]
    tables = [s for s in ddl if re.match(r"^\s*CREATE\s+TABLE", s.oracle_sql, re.I)]
    rest = [s for s in ddl if s not in seqs and s not in tables]
    deps = {name(t): set(x.lower() for x in re.findall(r"REFERENCES\s+([\w\"]+)", t.oracle_sql, re.I)) - {name(t)} for t in tables}
    ordered: list[Stmt] = []
    pending = list(tables)
    while pending:
        progressed = False
        for t in list(pending):
            if all(d not in {name(p) for p in pending} for d in deps[name(t)]):
                ordered.append(t)
                pending.remove(t)
                progressed = True
        if not progressed:
            ordered += pending
            break
    return seqs + ordered + rest


def _parallel(fn, items: list, workers: int) -> None:
    if not items:
        return
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(fn, items))


def _pair(ctx: RunContext) -> tuple[str, str]:
    return str(ctx.inputs.get("source_db") or dialects.DEFAULT_SOURCE), str(ctx.inputs.get("target_db") or dialects.DEFAULT_TARGET)


# ------------------------------------------------------------------------------------------- shared steps
def _setup_sandbox(ctx: RunContext) -> Sandbox:
    sb = Sandbox(settings.database_url, ctx.run.id)
    sb.setup()
    if sb.live:
        ctx.emit("Validator", f"Sandbox ready: PostgreSQL {sb.version}, isolated schema {sb.schema}", "ok")
    else:
        ctx.emit("Validator", f"No live PostgreSQL ({sb.error}); falling back to syntax-only validation", "warn")
    return sb


def _review(ctx: RunContext, stmts: list[Stmt], schema: SchemaInfo, depth: str = "non_trivial",
            focus: list[str] | None = None) -> None:
    done = [0]
    src, tgt = _pair(ctx)
    full = dialects.is_full(src, tgt)

    def one(s: Stmt) -> None:
        rule_risks = assess(s) if full else []
        llm_risks = []
        non_trivial = s.tier != "trivial" or s.method != "rules" or s.kind in ("plsql", "jdbc_call")
        wants_llm = s.status != "portable" and depth != "rules_only" and (non_trivial or depth == "all")
        if ctx.llm.available and wants_llm and s.pg_sql:
            llm_risks = review_with_llm(ctx.llm, s, schema, focus) if full else review_generic(ctx.llm, s, src, tgt, focus)
        s.risks = merge_risks(rule_risks, llm_risks)
        finalize(s)
        done[0] += 1

    ctx.emit("Risk Reviewer", f"Reviewing {len(stmts)} statements for semantic differences"
             + ({"all": " (rules + Claude on every non-portable statement)", "non_trivial": " (rules + Claude on the non-trivial ones)",
                 "rules_only": " (rules only, as planned by the Orchestrator)"}[depth] if ctx.llm.available else
             (" (rules only; no AI configured)" if full else " (no AI configured, so no semantic review for this database pair)")),
             "stage")
    _parallel(one, stmts, settings.llm_concurrency)
    high = sum(1 for s in stmts for r in s.risks if r.severity == "high")
    med = sum(1 for s in stmts for r in s.risks if r.severity == "medium")
    ctx.emit("Risk Reviewer", f"Found {high} high and {med} medium semantic risks that a passing query plan would not reveal", "ok" if not high else "warn")


def _summary_text(ctx: RunContext, stmts: list[Stmt], findings: list[Finding]) -> str | None:
    if not ctx.llm.available:
        return None
    from collections import Counter
    facts = {"statements": len(stmts), "status": dict(Counter(s.status for s in stmts)),
             "validation": dict(Counter(s.validation.get("status") for s in stmts)),
             "high_risks": [f"{s.label}: {r.category}" for s in stmts for r in s.risks if r.severity == "high"][:10],
             "findings": [f.category for f in findings][:8],
             "hours_manual": round(sum(s.baseline_min for s in stmts) / 60, 1),
             "hours_with_tool": round(sum(s.effort_min for s in stmts) / 60, 1)}
    return summarise_with_llm(ctx.llm, facts)


# ------------------------------------------------------------------------------------------- flow 1
def run_migration(ctx: RunContext) -> dict[str, Any]:
    """Supervisor graph. The Orchestrator node decides which worker agent runs next; every worker returns to it.
    With Claude available the Orchestrator also plans the run (how much AI to use, where to focus) after discovery and
    triages failures before the Critic gets involved. Without Claude it follows a deterministic default plan."""
    started = time.time()
    sandbox: Sandbox | None = None
    trace: list[dict[str, Any]] = []

    # Overall progress (percent) once each step has finished; the queries step fills 42..80 by itself.
    milestones = {"plan": 12, "code_reader": 22, "schema": 35, "plsql": 42, "queries": 80, "triage": 83, "critic": 88,
                  "review": 96, "report": 100}
    pct = [0]

    def progress(value: float) -> None:
        pct[0] = max(pct[0], min(100, round(value)))
        ctx.emit("Platform", "progress", "info", progress=[pct[0], 100])

    def note(step: str, agent: str, decision: str, reason: str = "") -> None:
        trace.append({"step": step, "agent": agent, "decision": decision, "reason": reason, "t": round(time.time() - started, 1)})
        if step in milestones:
            progress(milestones[step])

    try:
        def intake(state: FlowState) -> FlowState:
            src = ctx.inputs.get("source", "sample")
            ctx.emit("Intake", f"Source: {src}", "stage")
            progress(3)
            if src in ("sample", "sample2") and _pair(ctx)[0] != "oracle":
                raise RuntimeError("The bundled sample projects use Oracle. Upload your own project or choose Oracle as the source database.")
            if src == "sample":
                root, name = settings.sample_app_dir, "Acme Orders (synthetic Oracle demo app)"
                ctx.emit("Intake", "Using the bundled synthetic Oracle sample application", "info")
            elif src == "sample2":
                root, name = settings.sample_app_dir.parent / "hr-reports-oracle", "HR Reports (synthetic app that builds SQL in code)"
                ctx.emit("Intake", "Using the second bundled project, where SQL is assembled with StringBuilder and String.format", "info")
            else:
                dest = ctx.workdir / "src"
                try:
                    if src == "github":
                        url = str(ctx.inputs.get("github_url", ""))
                        ctx.emit("Intake", f"Fetching repository {url}", "info")
                        token = ctx.inputs.pop("github_token", None)  # used once, then dropped from memory
                        data, name = fetch_github_zip(url, settings.max_upload_bytes, token), url
                        ctx.emit("Intake", "Used your GitHub token for this download only" if token else "No token: public repositories only", "info")
                    else:
                        data, name = ctx.inputs["upload_bytes"], ctx.inputs.get("filename", "upload.zip")
                    n = safe_extract_zip(data, dest, max_files=settings.max_files)
                except UnsafeInput as exc:
                    raise RuntimeError(f"Rejected input: {exc}") from exc
                if n == 0:
                    raise RuntimeError("No Java, XML or SQL files found in the archive")
                ctx.emit("Intake", f"Accepted {n} source files (allow-listed types only, size-limited, zip-slip checked)", "ok")
                root = dest
            return {"root": root, "source_name": name, "done": ["intake"]}

        def discover(state: FlowState) -> FlowState:
            ctx.emit("Discovery", "Scanning Java, MyBatis XML, JPA native queries and SQL / PL/SQL scripts", "stage")
            stmts, findings, stats = extract.discover(state["root"], lambda a, m, l="info", **d: ctx.emit(a, m, l, **d),
                                                       settings.max_statements)
            from collections import Counter
            kinds = Counter(s.kind for s in stmts)
            ctx.emit("Discovery", f"Found {len(stmts)} statements ({', '.join(f'{v} {k}' for k, v in kinds.items())})", "ok",
                     kinds=dict(kinds))
            tiers = Counter(s.tier for s in stmts)
            ctx.emit("Discovery", f"Complexity: {tiers.get('trivial', 0)} trivial, {tiers.get('moderate', 0)} moderate, "
                                  f"{tiers.get('hard', 0)} hard", "info")
            for f in findings:
                if f.severity == "high" and "injection" in f.category.lower():
                    ctx.emit("Security", f"Possible prompt injection in {f.file}:{f.line} - treated as data, never as an instruction", "warn")
            hi = sum(1 for f in findings if f.severity == "high" and "injection" not in f.category.lower())
            if hi:
                ctx.emit("Security", f"{hi} high-severity application finding(s) (dynamic SQL, credentials, Oracle-only APIs)", "warn")
            return {"stmts": stmts, "findings": findings, "stats": stats, "done": state["done"] + ["discover"]}

        def plan(state: FlowState) -> Plan:
            """Orchestrator decision 1: how much of the AI team does this project need?"""
            from app.flows.oracle_pg import orchestrator as orch
            stats = state["stats"]
            if "reader" not in stats:  # cheap deterministic probe so the plan can use it
                files = sorted(p for p in state["root"].rglob("*") if p.is_file())
                gaps = reader.find_gaps(state["root"], files, state["stmts"])
                stats["reader"] = {"gap_files": len(gaps), "gap_fragments": sum(len(v) for v in gaps.values())}
            inv = orch.build_inventory(state["stmts"], state["findings"], stats, ctx.llm.available)
            raw = plan_with_llm(ctx.llm, inv) if ctx.llm.available else None
            p = orch.sanitize_plan(raw, inv)
            if ctx.llm.available and raw is None:
                ctx.emit("Orchestrator", f"Planning call failed ({ctx.llm.last_error}); using the default plan", "warn")
            ctx.emit("Orchestrator", f"Plan ({p.source}): Code Reader {'on' if p.run_code_reader else 'off'}, review depth {p.review_depth}, "
                                     f"Critic {'on' if p.run_critic else 'off'}, up to {p.max_repairs} repair(s). {p.rationale}", "ok", plan=p.to_dict())
            if p.focus:
                ctx.emit("Orchestrator", "Risk Reviewer focus: " + "; ".join(p.focus), "info")
            note("plan", "Orchestrator", f"{p.source} plan", p.rationale)
            return p

        def reader_node(state: FlowState) -> FlowState:
            ctx.emit("Code Reader", "Profiling the project and looking for SQL assembled in code", "stage")
            p: Plan = state["plan"]
            stmts = reader.run_reader(state["root"], state["stmts"], state["findings"], state["stats"], ctx.llm,
                                      lambda a, m, l="info", **d: ctx.emit(a, m, l, **d), use_llm=p.run_code_reader)
            note("code_reader", "Code Reader", f"{state['stats'].get('reader', {}).get('reconstructed', 0)} statements reconstructed")
            return {"stmts": stmts, "done": state["done"] + ["reader"]}

        def schema_node(state: FlowState) -> FlowState:
            nonlocal sandbox
            src, tgt = _pair(ctx)
            stmts = state["stmts"]
            ddl = [s for s in stmts if s.kind == "ddl"]
            emit = lambda a, m, l="info", **d: ctx.emit(a, m, l, **d)  # noqa: E731
            if dialects.is_full(src, tgt):
                sandbox = _setup_sandbox(ctx)
                schema = schema_from_ddl([s.oracle_sql for s in ddl])
                pipe = StmtPipeline(llm=ctx.llm, sandbox=sandbox, schema=schema, emit=emit, max_repairs=state["plan"].max_repairs)
            else:
                sandbox, schema = Sandbox(None, ctx.run.id), SchemaInfo()
                ctx.emit("Validator", f"{dialects.label(src)} to {dialects.label(tgt)}: no live {dialects.label(tgt)} database, "
                                      f"so statements are syntax-checked in the {dialects.label(tgt)} dialect only", "warn")
                pipe = GenericPipeline(llm=ctx.llm, src=src, tgt=tgt, emit=emit, max_repairs=state["plan"].max_repairs)
            if ddl:
                ctx.emit("Converter", f"Converting and applying {len(ddl)} schema statements in dependency order", "stage")
                for s in _order_ddl(ddl):
                    pipe.run(s)
                if sandbox.live:
                    live = sandbox.introspect()
                    if live.tables:
                        schema.tables = {t: {c: ty for c, ty in cols.items()} for t, cols in live.tables.items()}
            note("schema", "Converter", f"{len(ddl)} schema statements")
            return {"schema": schema, "pipeline": pipe, "done": state["done"] + ["schema"]}

        def plsql_node(state: FlowState) -> FlowState:
            units = [s for s in state["stmts"] if s.kind == "plsql"]
            if units:
                ctx.emit("Converter", f"Converting {len(units)} procedural unit(s)", "stage")
                _parallel(state["pipeline"].run, units, settings.llm_concurrency)
            note("plsql", "Converter", f"{len(units)} PL/SQL units")
            return {"done": state["done"] + ["plsql"]}

        def queries_node(state: FlowState) -> FlowState:
            qs = [s for s in state["stmts"] if s.kind not in ("ddl", "plsql")]
            ctx.emit("Converter", f"Converting {len(qs)} queries / DML statements (rules first, AI for the hard ones)", "stage")
            counter = [0]

            def one(s: Stmt) -> None:
                state["pipeline"].run(s)
                counter[0] += 1
                ctx.emit("Platform", f"{counter[0]}/{len(qs)} statements processed", "info", progress=[round(42 + 38 * counter[0] / max(len(qs), 1)), 100])

            # jdbc_call statements depend on PL/SQL results, so they go last
            _parallel(one, [s for s in qs if s.kind != "jdbc_call"], settings.llm_concurrency)
            _parallel(one, [s for s in qs if s.kind == "jdbc_call"], 1)
            note("queries", "Converter", f"{len(qs)} statements")
            return {"done": state["done"] + ["queries"]}

        def critic_node(state: FlowState) -> FlowState:
            """Orchestrator decision 2 (triage) -> Critic diagnoses -> Converter retries -> Validator -> Risk Reviewer."""
            from app.flows.oracle_pg import orchestrator as orch
            stmts, pipe, schema, p = state["stmts"], state["pipeline"], state["schema"], state["plan"]
            failing = orch.failing_statements(stmts)
            if not failing:
                ctx.emit("Critic", "Nothing is failing validation; no second opinion needed", "ok")
                note("critic", "Critic", "skipped: nothing failing")
                return {"done": state["done"] + ["critic"]}
            ctx.emit("Orchestrator", f"{len(failing)} statement(s) still fail or need manual work; deciding which are worth one more attempt", "stage")
            tri = triage_with_llm(ctx.llm, orch.triage_payload(failing)) or {}
            by_id = {s.id: s for s in failing}
            retry = [by_id[i] for i in dict.fromkeys(tri.get("retry_ids", [])) if i in by_id][:6]
            note("triage", "Orchestrator", f"retry {len(retry)} of {len(failing)}", str(tri.get("rationale", ""))[:300])
            ctx.emit("Orchestrator", f"Retrying {len(retry)} of {len(failing)}: {str(tri.get('rationale', 'no rationale'))[:200]}", "info")
            fixed = 0

            def work(s: Stmt) -> None:
                nonlocal fixed
                crit = critique_with_llm(ctx.llm, s, schema)
                if not crit:
                    return
                if crit.get("give_up"):
                    s.notes.append(f"Critic: needs a human. {str(crit.get('give_up_reason') or crit.get('diagnosis', ''))[:240]}")
                    ctx.emit("Critic", f"{s.id} {s.label}: needs a human ({str(crit.get('give_up_reason') or crit.get('diagnosis', ''))[:140]})", "warn", id=s.id)
                    return
                ctx.emit("Critic", f"{s.id} {s.label}: {str(crit.get('diagnosis', ''))[:160]}", "info", id=s.id)
                s.meta["critic_hint"] = str(crit.get("instruction", ""))[:700]
                s.notes.append(f"Critic diagnosis: {str(crit.get('diagnosis', ''))[:240]}")
                s.attempts = 0
                before = s.validation.get("status")
                pipe.run(s)
                s.meta.pop("critic_hint", None)
                if before == "failed" and s.validation.get("status") in ("ok", "inconclusive"):
                    fixed += 1
                    s.notes.append("Fixed after the Critic's second opinion")

            _parallel(work, retry, settings.llm_concurrency)
            if retry:
                _review(ctx, retry, schema, p.review_depth, p.focus)  # refresh risks and status for the retried ones only
            ctx.emit("Critic", f"Second round finished: {fixed} of {len(retry)} retried statement(s) now pass", "ok" if fixed else "info")
            note("critic", "Critic", f"{fixed} of {len(retry)} fixed")
            return {"done": state["done"] + ["critic"]}

        def review_node(state: FlowState) -> FlowState:
            p: Plan = state["plan"]
            _review(ctx, state["stmts"], state["schema"], p.review_depth, p.focus)
            note("review", "Risk Reviewer", f"depth {p.review_depth}")
            return {"done": state["done"] + ["review"]}

        def report_node(state: FlowState) -> FlowState:
            ctx.emit("Report", "Assembling report, effort estimate and migration checklist", "stage")
            summary_text = _summary_text(ctx, state["stmts"], state["findings"])
            full_pair = dialects.is_full(*_pair(ctx))  # the "App change needed" advice names Oracle and PostgreSQL specifically
            findings = [f for f in state["findings"] if full_pair or not f.category.startswith("App change needed")]
            rep = build_report(run_id=ctx.run.id, source_name=state["source_name"], stmts=state["stmts"], findings=findings,
                               stats=state["stats"], sandbox=sandbox, llm=ctx.llm, started=started, executive_summary=summary_text,
                               pair=_pair(ctx))
            rep["meta"]["orchestration"] = {"plan": state["plan"].to_dict(), "trace": trace, "ai": ctx.llm.describe()}
            s = rep["summary"]
            ctx.emit("Report", f"{s['auto_rate_pct']}% auto/portable, {s['by_status'].get('review', 0)} to review, "
                               f"{s['by_status'].get('manual', 0)} manual; effort {s['effort']['assisted_hours']} h vs "
                               f"{s['effort']['baseline_hours']} h by hand", "ok")
            note("report", "Report", "done")
            return {"report": rep, "done": state["done"] + ["report"]}

        # ---- the supervisor: after every worker, decide who is next
        def orchestrator_node(state: FlowState) -> FlowState:
            done = state.get("done", [])
            out: FlowState = {}
            if "discover" in done and not state.get("plan"):
                out["plan"] = plan(state)
            p = out.get("plan") or state.get("plan")
            nxt = "intake"
            for step in ("intake", "discover", "reader", "schema", "plsql", "queries", "review", "critic", "report"):
                if step in done:
                    continue
                if step == "critic" and (not p or not p.run_critic or not ctx.llm.available):
                    continue
                if step == "plsql" and not any(s.kind == "plsql" for s in state.get("stmts", [])):
                    continue
                nxt = step
                break
            out["next"] = nxt
            return out

        workers = {"intake": intake, "discover": discover, "reader": reader_node, "schema": schema_node, "plsql": plsql_node,
                   "queries": queries_node, "review": review_node, "critic": critic_node, "report": report_node}
        g = StateGraph(FlowState)
        g.add_node("orchestrator", orchestrator_node)
        for name, fn in workers.items():
            g.add_node(name, fn)
            if name != "report":
                g.add_edge(name, "orchestrator")
        g.set_entry_point("orchestrator")
        g.add_conditional_edges("orchestrator", lambda st: st["next"], {**{k: k for k in workers}})
        g.add_edge("report", END)
        final = g.compile().invoke({"done": []}, {"recursion_limit": 60})
        return final["report"]
    finally:
        if sandbox is not None:
            sandbox.teardown()


# ------------------------------------------------------------------------------------------- flow 2
def run_snippet(ctx: RunContext) -> dict[str, Any]:
    started = time.time()
    src, tgt = _pair(ctx)
    full = dialects.is_full(src, tgt)
    sl = dialects.label(src)
    sql = str(ctx.inputs.get("sql", "")).strip()
    if not sql:
        raise RuntimeError(f"Paste a {sl} SQL statement" + (" or PL/SQL block" if src == "oracle" else ""))
    if len(sql) > 20_000:
        raise RuntimeError("Snippet is larger than 20,000 characters")
    ctx.emit("Intake", f"Received {len(sql)} characters ({sl} to {dialects.label(tgt)})", "stage")
    ctx.emit("Platform", "progress", "info", progress=[10, 100])
    sandbox = _setup_sandbox(ctx) if full else Sandbox(None, ctx.run.id)
    try:
        if full:
            ddl_text = str(ctx.inputs.get("schema_sql", "")).strip()
            if not ddl_text:
                ddl_text = (settings.sample_app_dir / "schema" / "oracle_schema.sql").read_text("utf-8")
                ctx.emit("Intake", "No schema supplied: validating against the bundled Acme Orders demo schema", "info")
            seq = iter(range(1, 1000))
            counter = lambda: f"S{next(seq):03d}"  # noqa: E731
            ddl_stmts = [Stmt(id=counter(), kind="ddl", file="schema", line=l, label="schema", oracle_sql=t)
                         for l, t in extract._split_script(ddl_text)]
            schema = schema_from_ddl([s.oracle_sql for s in ddl_stmts])
            pipe = StmtPipeline(llm=ctx.llm, sandbox=sandbox, schema=schema,
                                emit=lambda a, m, l="info", **d: ctx.emit(a, m, l, **d) if a != "Converter" or l != "info" else None,
                                max_repairs=settings.max_repair_attempts)
            for s in _order_ddl(ddl_stmts):
                pipe.run(s)
            if sandbox.live:
                live = sandbox.introspect()
                if live.tables:
                    schema.tables = live.tables
            pipe.emit = lambda a, m, l="info", **d: ctx.emit(a, m, l, **d)
        else:
            schema = SchemaInfo()
            ctx.emit("Validator", f"No live {dialects.label(tgt)} database for this pair: the result is syntax-checked in the "
                                  f"{dialects.label(tgt)} dialect only", "warn")
            pipe = GenericPipeline(llm=ctx.llm, src=src, tgt=tgt, emit=lambda a, m, l="info", **d: ctx.emit(a, m, l, **d),
                                   max_repairs=settings.max_repair_attempts)

        kind = extract._kind_for_sql(sql, "jdbc")
        if kind == "jdbc" and not extract.looks_like_sql(sql):
            raise RuntimeError(f"That does not look like a {sl} SQL statement" + (" or PL/SQL block" if src == "oracle" else ""))
        st = Stmt(id="S001", kind=kind, file="snippet", line=1, label="Pasted snippet", oracle_sql=sql.rstrip().rstrip(";") if kind != "plsql" else sql)
        st.constructs, st.weight = detect(st.oracle_sql, st.kind)
        st.tier = tier_for(st.kind, st.weight)
        ctx.emit("Discovery", f"Detected {kind}" + (f"; Oracle constructs: {', '.join(st.constructs) or 'none'}" if src == "oracle" else ""), "ok")
        ctx.emit("Platform", "progress", "info", progress=[35, 100])
        pipe.run(st)
        ctx.emit("Platform", "progress", "info", progress=[70, 100])
        _review(ctx, [st], schema)
        ctx.emit("Platform", "progress", "info", progress=[95, 100])
        rep = build_report(run_id=ctx.run.id, source_name="Pasted snippet", stmts=[st], findings=[], stats={"files": 0},
                           sandbox=sandbox, llm=ctx.llm, started=started, pair=(src, tgt))
        return rep
    finally:
        sandbox.teardown()


# ------------------------------------------------------------------------------------------- registration
AGENTS = [
    {"name": "Orchestrator", "role": "The supervisor: plans how much of the AI team this project needs, routes work between agents, and triages failures for a second attempt."},
    {"name": "Discovery", "role": "Finds every SQL statement in Java, MyBatis XML, JPA and SQL files; tags database-specific constructs; scans for prompt injection and unsafe SQL."},
    {"name": "Code Reader", "role": "Profiles a new Java project (frameworks, build tool, where the SQL lives) and has the AI reconstruct SQL that the code assembles at runtime."},
    {"name": "Converter", "role": "Rules engine (sqlglot plus custom rewrites) first; the AI only for what the rules cannot do; repair loop on validator errors."},
    {"name": "Validator", "role": "Checks every converted statement: planned on a real PostgreSQL sandbox when the target is PostgreSQL (EXPLAIN only, rolled back, time-limited), syntax-checked in the target dialect otherwise."},
    {"name": "Critic", "role": "Diagnoses statements that still fail and gives the Converter a concrete instruction for one more attempt, or hands them to a human."},
    {"name": "Risk Reviewer", "role": "Flags semantic differences that still run: NULL vs empty string, row-limit and ordering, date and time types, concatenation with NULL, transactions."},
    {"name": "Report", "role": "Confidence per statement, effort estimate vs manual, application checklist, downloadable report."},
]

register(FlowDef(
    id="oracle-java-migration",
    title="Java application converter",
    tagline="Upload a SQL-heavy Java repo, get converted, checked, risk-ranked SQL",
    description="Extracts SQL from JDBC strings, MyBatis mappers, JPA native queries and stored procedures, converts it between the two "
                "databases you pick with a hybrid rules + AI pipeline, checks the result (on a real PostgreSQL sandbox when the target "
                "is PostgreSQL), and reports what still needs a human.",
    agents=AGENTS,
    inputs=[
        {"name": "source", "type": "choice", "label": "Which application?", "default": "sample",
         "options": [{"value": "upload", "label": "New project: upload a .zip"},
                     {"value": "github", "label": "New project: public GitHub URL"},
                     {"value": "sample", "label": "Bundled sample app (Oracle)"},
                     {"value": "sample2", "label": "Bundled sample 2 (Oracle, SQL built in code)"}]},
        {"name": "upload", "type": "file", "label": "Repository zip", "show_when": {"source": "upload"}},
        {"name": "github_url", "type": "text", "label": "GitHub URL", "placeholder": "https://github.com/owner/repo",
         "show_when": {"source": "github"}},
        {"name": "github_token", "type": "secret", "label": "GitHub personal access token (only for private repositories)",
         "optional": True, "show_when": {"source": "github"},
         "hint": "Fine-grained token with read-only Contents access. Used for this download only; never stored or logged."},
    ],
    runner=run_migration,
))

register(FlowDef(
    id="sql-snippet-converter",
    title="SQL snippet converter",
    tagline="Paste one statement, get it in the other database, checked, with the risks",
    description="The same Converter, Validator and Risk Reviewer agents on a single pasted statement. For Oracle to PostgreSQL you can "
                "also paste your DDL so the statement is planned against your own tables.",
    agents=[a for a in AGENTS if a["name"] in ("Converter", "Validator", "Risk Reviewer")],
    inputs=[
        {"name": "sql", "type": "textarea", "label": "SQL to convert", "placeholder": "SELECT ... FROM ... WHERE ..."},
        {"name": "schema_sql", "type": "textarea", "label": "Optional: Oracle DDL for your tables (Oracle to PostgreSQL only)", "optional": True,
         "placeholder": "CREATE TABLE ... (leave empty to use the demo schema)"},
    ],
    runner=run_snippet,
))
