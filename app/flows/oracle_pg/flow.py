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
from app.core.registry import FlowDef, RunContext, register
from app.core.security import Finding, UnsafeInput, fetch_github_zip, safe_extract_zip
from app.flows.oracle_pg import extract, reader
from app.flows.oracle_pg.constructs import detect, tier_for
from app.flows.oracle_pg.llm_agents import review_with_llm, summarise_with_llm
from app.flows.oracle_pg.models import Stmt
from app.flows.oracle_pg.report import build_report
from app.flows.oracle_pg.risk import assess, finalize, merge_risks
from app.flows.oracle_pg.rules import SchemaInfo, schema_from_ddl
from app.flows.oracle_pg.sandbox import Sandbox
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


# ------------------------------------------------------------------------------------------- shared steps
def _setup_sandbox(ctx: RunContext) -> Sandbox:
    sb = Sandbox(settings.database_url, ctx.run.id)
    sb.setup()
    if sb.live:
        ctx.emit("Validator", f"Sandbox ready: PostgreSQL {sb.version}, isolated schema {sb.schema}", "ok")
    else:
        ctx.emit("Validator", f"No live PostgreSQL ({sb.error}); falling back to syntax-only validation", "warn")
    return sb


def _review(ctx: RunContext, stmts: list[Stmt], schema: SchemaInfo) -> None:
    done = [0]

    def one(s: Stmt) -> None:
        rule_risks = assess(s)
        llm_risks = []
        wants_llm = s.status != "portable" and (s.tier != "trivial" or s.method != "rules" or s.kind in ("plsql", "jdbc_call"))
        if ctx.llm.available and wants_llm and s.pg_sql:
            llm_risks = review_with_llm(ctx.llm, s, schema)
        s.risks = merge_risks(rule_risks, llm_risks)
        finalize(s)
        done[0] += 1

    ctx.emit("Risk Reviewer", f"Reviewing {len(stmts)} statements for semantic differences"
             + (" (rules + Claude on the non-trivial ones)" if ctx.llm.available else " (rules only; no LLM configured)"), "stage")
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
    started = time.time()
    sandbox: Sandbox | None = None
    try:
        def intake(state: FlowState) -> FlowState:
            src = ctx.inputs.get("source", "sample")
            ctx.emit("Intake", f"Source: {src}", "stage")
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
                        ctx.emit("Intake", f"Fetching public repository {url}", "info")
                        data, name = fetch_github_zip(url, settings.max_upload_bytes), url
                    else:
                        data, name = ctx.inputs["upload_bytes"], ctx.inputs.get("filename", "upload.zip")
                    n = safe_extract_zip(data, dest, max_files=settings.max_files)
                except UnsafeInput as exc:
                    raise RuntimeError(f"Rejected input: {exc}") from exc
                if n == 0:
                    raise RuntimeError("No Java, XML or SQL files found in the archive")
                ctx.emit("Intake", f"Accepted {n} source files (allow-listed types only, size-limited, zip-slip checked)", "ok")
                root = dest
            return {"root": root, "source_name": name}

        def discover(state: FlowState) -> FlowState:
            ctx.emit("Discovery", "Scanning Java, MyBatis XML, JPA native queries and SQL / PL/SQL scripts", "stage")
            stmts, findings, stats = extract.discover(state["root"], lambda a, m, l="info", **d: ctx.emit(a, m, l, **d),
                                                       settings.max_statements)
            from collections import Counter
            ctx.emit("Code Reader", "Profiling the project and looking for SQL assembled in code", "stage")
            stmts = reader.run_reader(state["root"], stmts, findings, stats, ctx.llm, lambda a, m, l="info", **d: ctx.emit(a, m, l, **d))
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
            return {"stmts": stmts, "findings": findings, "stats": stats}

        def migrate_schema(state: FlowState) -> FlowState:
            nonlocal sandbox
            sandbox = _setup_sandbox(ctx)
            stmts = state["stmts"]
            ddl = [s for s in stmts if s.kind == "ddl"]
            schema = schema_from_ddl([s.oracle_sql for s in ddl])
            pipe = StmtPipeline(llm=ctx.llm, sandbox=sandbox, schema=schema,
                                emit=lambda a, m, l="info", **d: ctx.emit(a, m, l, **d), max_repairs=settings.max_repair_attempts)
            if ddl:
                ctx.emit("Converter", f"Converting and applying {len(ddl)} schema statements in dependency order", "stage")
                for s in _order_ddl(ddl):
                    pipe.run(s)
                if sandbox.live:
                    live = sandbox.introspect()
                    if live.tables:
                        schema.tables = {t: {c: ty for c, ty in cols.items()} for t, cols in live.tables.items()}
            return {"schema": schema, "pipeline": pipe}

        def convert_plsql(state: FlowState) -> FlowState:
            units = [s for s in state["stmts"] if s.kind == "plsql"]
            if units:
                ctx.emit("Converter", f"Converting {len(units)} PL/SQL unit(s) to PL/pgSQL", "stage")
                _parallel(state["pipeline"].run, units, settings.llm_concurrency)
            return {}

        def convert_queries(state: FlowState) -> FlowState:
            qs = [s for s in state["stmts"] if s.kind not in ("ddl", "plsql")]
            ctx.emit("Converter", f"Converting {len(qs)} queries / DML statements (rules first, Claude for the hard ones)", "stage")
            counter = [0]

            def one(s: Stmt) -> None:
                state["pipeline"].run(s)
                counter[0] += 1
                ctx.emit("Platform", f"{counter[0]}/{len(qs)} statements processed", "info", progress=[counter[0], len(qs)])

            # jdbc_call statements depend on PL/SQL results, so they go last
            _parallel(one, [s for s in qs if s.kind != "jdbc_call"], settings.llm_concurrency)
            _parallel(one, [s for s in qs if s.kind == "jdbc_call"], 1)
            return {}

        def review(state: FlowState) -> FlowState:
            _review(ctx, state["stmts"], state["schema"])
            return {}

        def report(state: FlowState) -> FlowState:
            ctx.emit("Report", "Assembling report, effort estimate and migration checklist", "stage")
            summary_text = _summary_text(ctx, state["stmts"], state["findings"])
            rep = build_report(run_id=ctx.run.id, source_name=state["source_name"], stmts=state["stmts"], findings=state["findings"],
                               stats=state["stats"], sandbox=sandbox, llm=ctx.llm, started=started, executive_summary=summary_text)
            s = rep["summary"]
            ctx.emit("Report", f"{s['auto_rate_pct']}% auto/portable, {s['by_status'].get('review', 0)} to review, "
                               f"{s['by_status'].get('manual', 0)} manual; effort {s['effort']['assisted_hours']} h vs "
                               f"{s['effort']['baseline_hours']} h by hand", "ok")
            return {"report": rep}

        g = StateGraph(FlowState)
        for name, fn in [("intake", intake), ("discover", discover), ("migrate_schema", migrate_schema),
                         ("convert_plsql", convert_plsql), ("convert_queries", convert_queries),
                         ("review", review), ("report", report)]:
            g.add_node(name, fn)
        g.set_entry_point("intake")
        order = ["intake", "discover", "migrate_schema", "convert_plsql", "convert_queries", "review", "report"]
        for a, b in zip(order, order[1:]):
            g.add_edge(a, b)
        g.add_edge("report", END)
        final = g.compile().invoke({})
        return final["report"]
    finally:
        if sandbox is not None:
            sandbox.teardown()


# ------------------------------------------------------------------------------------------- flow 2
def run_snippet(ctx: RunContext) -> dict[str, Any]:
    started = time.time()
    sql = str(ctx.inputs.get("sql", "")).strip()
    if not sql:
        raise RuntimeError("Paste an Oracle SQL statement or PL/SQL block")
    if len(sql) > 20_000:
        raise RuntimeError("Snippet is larger than 20,000 characters")
    ctx.emit("Intake", f"Received {len(sql)} characters", "stage")
    sandbox = _setup_sandbox(ctx)
    try:
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

        kind = extract._kind_for_sql(sql, "jdbc")
        if kind == "jdbc" and not extract.looks_like_sql(sql):
            raise RuntimeError("That does not look like an Oracle SQL statement or PL/SQL block")
        st = Stmt(id="S001", kind=kind, file="snippet", line=1, label="Pasted snippet", oracle_sql=sql.rstrip().rstrip(";") if kind != "plsql" else sql)
        st.constructs, st.weight = detect(st.oracle_sql, st.kind)
        st.tier = tier_for(st.kind, st.weight)
        ctx.emit("Discovery", f"Detected {kind}; Oracle constructs: {', '.join(st.constructs) or 'none'}", "ok")
        pipe.run(st)
        _review(ctx, [st], schema)
        rep = build_report(run_id=ctx.run.id, source_name="Pasted snippet", stmts=[st], findings=[], stats={"files": 0},
                           sandbox=sandbox, llm=ctx.llm, started=started)
        return rep
    finally:
        sandbox.teardown()


# ------------------------------------------------------------------------------------------- registration
AGENTS = [
    {"name": "Discovery", "role": "Finds every SQL statement in Java, MyBatis XML, JPA and SQL files; tags Oracle constructs; scans for prompt injection and unsafe SQL."},
    {"name": "Code Reader", "role": "Profiles a new Java project (frameworks, build tool, where the SQL lives) and has Claude reconstruct SQL that the code assembles at runtime (StringBuilder chains, string formatting, helper methods)."},
    {"name": "Converter", "role": "Rules engine (sqlglot + custom rewrites) first; Claude only for what the rules cannot do; repair loop on validator errors."},
    {"name": "Validator", "role": "Plans every converted statement on a real PostgreSQL sandbox (EXPLAIN only, rolled back, time-limited)."},
    {"name": "Risk Reviewer", "role": "Flags semantic differences that still run: '' vs NULL, ROWNUM order, DATE time part, concat NULLs, transactions."},
    {"name": "Report", "role": "Confidence per statement, effort estimate vs manual, application checklist, downloadable report."},
]

register(FlowDef(
    id="oracle-java-migration",
    title="Oracle to PostgreSQL: Java application",
    tagline="Upload a SQL-heavy Java repo, get converted, validated, risk-ranked SQL",
    description="Extracts SQL from JDBC strings, MyBatis mappers, JPA native queries and PL/SQL, converts it with a hybrid "
                "rules + Claude pipeline, validates on a real PostgreSQL sandbox, and reports what still needs a human.",
    agents=AGENTS,
    inputs=[
        {"name": "source", "type": "choice", "label": "Which application?", "default": "sample",
         "options": [{"value": "upload", "label": "New project: upload a .zip"},
                     {"value": "github", "label": "New project: public GitHub URL"},
                     {"value": "sample", "label": "Bundled sample app"},
                     {"value": "sample2", "label": "Bundled sample 2 (SQL built in code)"}]},
        {"name": "upload", "type": "file", "label": "Repository zip", "show_when": {"source": "upload"}},
        {"name": "github_url", "type": "text", "label": "GitHub URL", "placeholder": "https://github.com/owner/repo",
         "show_when": {"source": "github"}},
    ],
    runner=run_migration,
))

register(FlowDef(
    id="sql-snippet-converter",
    title="Oracle SQL / PL/SQL snippet converter",
    tagline="Paste one statement, get PostgreSQL, a live plan check and the risks",
    description="The same Converter, Validator and Risk Reviewer agents on a single pasted statement. Optionally paste your DDL so "
                "the statement is validated against your own tables.",
    agents=[a for a in AGENTS if a["name"] in ("Converter", "Validator", "Risk Reviewer")],
    inputs=[
        {"name": "sql", "type": "textarea", "label": "Oracle SQL or PL/SQL", "placeholder": "SELECT ... FROM ... WHERE ROWNUM <= 10"},
        {"name": "schema_sql", "type": "textarea", "label": "Optional: Oracle DDL for your tables", "optional": True,
         "placeholder": "CREATE TABLE ... (leave empty to use the demo schema)"},
    ],
    runner=run_snippet,
))
