"""Risk Reviewer (deterministic half): semantic differences that still *run* on PostgreSQL but may behave differently.
These are exactly the findings that a green EXPLAIN does not catch."""
from __future__ import annotations

import re

from app.flows.oracle_pg.constructs import mask_strings
from app.flows.oracle_pg.models import Risk, Stmt

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def assess(stmt: Stmt) -> list[Risk]:
    sql = stmt.oracle_sql
    masked = mask_strings(sql)
    flags = set(stmt.meta.get("flags", []))
    notes_blob = " | ".join(stmt.notes).lower()
    pg = stmt.pg_sql or ""
    out: list[Risk] = []

    def add(cat: str, sev: str, msg: str, fix: str = "") -> None:
        if not any(r.category == cat for r in out):
            out.append(Risk(cat, sev, msg, fix, "rule"))

    if stmt.kind in ("jpql",):
        return out

    if re.search(r"(=|<>|!=)\s*''", sql):
        add("Empty string vs NULL", "high",
            "Oracle treats '' as NULL, so `col = ''` is never true there. In PostgreSQL '' is an empty string and "
            "matches, while `IS NULL` no longer matches empty strings.",
            "Decide the intended behaviour; NULLIF(col, '') IS NULL reproduces Oracle's meaning.")
    if "rownum_before_order" in flags:
        add("ROWNUM applied before ORDER BY / GROUP BY", "high",
            "In Oracle ROWNUM is evaluated before ORDER BY and GROUP BY at the same query level, so the original "
            "returns an arbitrary subset. LIMIT in PostgreSQL applies after sorting/grouping and returns different rows.",
            "Confirm intent. If a true top-N was meant, ORDER BY in a subquery then LIMIT (the PostgreSQL result is the intended one).")
    if "rownum_delete_ctid" in flags:
        add("Batch delete via ctid", "medium",
            "DELETE ... ROWNUM <= n was rewritten with ctid. It works, but ctid is physical and not a stable key under concurrent updates.",
            "Prefer batching by primary key (WHERE id IN (SELECT id ... LIMIT n)).")
    if "rownum_paging" in flags:
        add("Paging column RN dropped", "low",
            "Two-level ROWNUM paging became LIMIT/OFFSET and the RN column is no longer returned. OFFSET gets slow on deep pages.",
            "If callers read RN add ROW_NUMBER() OVER (...); consider keyset pagination for large tables.")
    if "hint_dropped" in flags:
        add("Optimizer hints removed", "low",
            "Oracle hints have no PostgreSQL equivalent and were dropped; the planner may pick a different plan.",
            "Re-check with EXPLAIN (ANALYZE, BUFFERS) on production-sized data; add or adjust indexes if needed.")
    if "decode_null" in flags:
        add("DECODE NULL semantics", "medium",
            "DECODE treats NULL = NULL as a match; the CASE expression it becomes does not.",
            "Add explicit IS NULL branches where the original relied on NULL matching.")
    if stmt.meta.get("reader") == "llm":
        add("Reconstructed from Java code by Claude", "medium",
            "This statement is assembled at runtime in the Java code; Claude rebuilt the full text from the file"
            + (f" ({stmt.meta['reader_note']})" if stmt.meta.get("reader_note") else "")
            + ". Optional clauses may be missing or ordered differently from the real code paths.",
            "Compare against the Java method and test each branch (optional filters, sort columns) after migration.")
    if stmt.dynamic or stmt.meta.get("raw_substitution"):
        add("Dynamic SQL", "high",
            "The statement is assembled from string concatenation or ${} substitution, so it cannot be fully validated "
            "and is open to SQL injection.",
            "Rewrite with bind parameters / a whitelist of identifiers, then re-run the migration check.")
    if stmt.meta.get("result_map"):
        add("Result map keys change case", "medium",
            "With resultType=map, Oracle returns UPPER-case column keys; PostgreSQL returns lower-case keys. "
            "Code like row.get(\"CUSTOMER_ID\") will return null.",
            "Use lower-case keys, a case-insensitive map, or explicit column aliases in quotes.")
    if stmt.kind != "ddl" and "||" in masked:
        add("NULL inside string concatenation", "medium",
            "In Oracle `a || NULL` returns a; in PostgreSQL the whole result becomes NULL.",
            "Use CONCAT(...) or COALESCE(col, '') for nullable operands.")
    if stmt.kind not in ("ddl", "plsql") and re.search(r"[\w)]\s*/\s*[\w(]", masked.replace("/*", "").replace("*/", "")):
        add("Integer division", "low",
            "Oracle NUMBER division is always exact; NUMBER columns with scale 0 are mapped to INTEGER/BIGINT where `a / b` truncates.",
            "Verify operand types; cast one side to NUMERIC where fractions are expected.")
    if re.match(r"^\s*MERGE\b", sql, re.I):
        add("MERGE semantics and version", "medium",
            "MERGE needs PostgreSQL 15+, and under concurrency it can raise unique violations instead of upserting atomically.",
            "Consider INSERT ... ON CONFLICT DO UPDATE for single-row upserts; confirm the target PostgreSQL version.")
    if re.search(r"\b\w+\.NEXTVAL\b", masked, re.I) or "nextval(" in pg.lower():
        add("Sequence behaviour", "low",
            "PostgreSQL sequences are non-transactional and may leave gaps. After data migration, sequences must be advanced with setval().",
            "Add a post-load step that sets each sequence to MAX(id)+1.")
    if stmt.shims:
        add("Compat shim required", "medium",
            f"Uses Oracle-style functions ({', '.join(stmt.shims)}) that exist only through compat_shims.sql in PostgreSQL.",
            "Deploy the shim functions to the target database or rewrite the calls natively.")
    if "REGEXP_* functions" in stmt.constructs:
        add("Regular expression dialect", "medium",
            "Oracle regex (POSIX ERE with extensions) and PostgreSQL regex (ARE) differ in classes, lazy quantifiers and flags.",
            "Re-test every pattern with representative data.")
    if re.search(r"TO_(CHAR|DATE|TIMESTAMP)\s*\([^)]*'[^']*(RR|RRRR|DY|DAY|MON|MONTH|FM|D)\b", sql, re.I):
        add("Date format model", "medium",
            "Some Oracle format tokens (RR, DY, MON, FM, D) behave differently or depend on session language in PostgreSQL.",
            "Check the output for the formats used; set lc_time explicitly if names are displayed.")
    if "date_trunc" in notes_blob or "interval" in notes_blob or "localtimestamp" in notes_blob:
        add("DATE has a time part", "medium",
            "Oracle DATE carries time of day and no time zone. It is mapped to TIMESTAMP(0), and SYSDATE to LOCALTIMESTAMP(0); "
            "date arithmetic was rewritten with intervals.",
            "Confirm the JDBC session time zone and that no column was meant to be a pure date.")
    if stmt.kind == "jdbc_call":
        add("Stored procedure call / OUT parameters", "high",
            "PostgreSQL JDBC maps {call ...} to functions; OUT parameters and REF CURSORs behave differently, and procedures "
            "that commit need CALL semantics.",
            "Retest the call with registerOutParameter; consider calling the function with SELECT ... FROM func(...).")
    if stmt.kind == "plsql":
        if re.search(r"AUTONOMOUS_TRANSACTION", sql, re.I):
            add("Autonomous transaction", "high",
                "PostgreSQL has no autonomous transactions: the logging insert now rolls back with the caller.",
                "Use dblink/pg_background for true autonomy, or accept in-transaction logging.")
        if re.search(r"\b(COMMIT|ROLLBACK)\b", masked, re.I):
            add("Transaction control inside PL/SQL", "high",
                "PL/pgSQL functions cannot COMMIT/ROLLBACK, and an exception rolls back to the block's implicit savepoint.",
                "Move transaction control to the caller, or use a PROCEDURE invoked with CALL outside any transaction block.")
        if re.search(r"\bSELECT\b[^;]*\bINTO\b", masked, re.I):
            add("SELECT INTO without STRICT", "medium",
                "Oracle raises NO_DATA_FOUND / TOO_MANY_ROWS for SELECT INTO; PL/pgSQL only does so with STRICT.",
                "Add STRICT where the handler relies on those exceptions.")
        if "BULK COLLECT / FORALL" in stmt.constructs:
            add("Bulk operations", "medium", "BULK COLLECT / FORALL have no direct equivalent; set-based SQL or loops are used instead.",
                "Prefer a single set-based statement; benchmark with production volumes.")
        if "RAISE_APPLICATION_ERROR" in stmt.constructs:
            add("Custom error codes", "medium", "RAISE_APPLICATION_ERROR(-20xxx) becomes RAISE EXCEPTION with an SQLSTATE; "
                "Java code that checks error codes must be updated.", "Define a documented SQLSTATE mapping (e.g. P0001).")
        add("Package state / schema layout", "low", "Package-level variables and overloads have no direct equivalent; packages become schemas.",
            "Review package globals and any code relying on session-level package state.")
    if stmt.kind == "ddl" and "date" in notes_blob:
        add("DATE columns mapped to TIMESTAMP(0)", "medium",
            "Oracle DATE contains a time; mapping to PostgreSQL DATE would silently drop it.", "Keep TIMESTAMP(0) unless the column is date-only.")
    if stmt.kind == "ddl" and "integer" in notes_blob or "bigint" in notes_blob:
        add("NUMBER mapped to integer types", "low",
            "NUMBER(p,0) became INTEGER/BIGINT for performance. Values or arithmetic outside that range, and integer division, behave differently.",
            "Use NUMERIC if columns can exceed 18 digits or are used in fractional arithmetic.")
    out.sort(key=lambda r: SEV_ORDER[r.severity])
    return out


def merge_risks(rule_risks: list[Risk], llm_risks: list[Risk]) -> list[Risk]:
    seen = {r.category.lower() for r in rule_risks}
    merged = list(rule_risks)
    for r in llm_risks:
        if r.category.lower() not in seen:
            merged.append(r)
            seen.add(r.category.lower())
    merged.sort(key=lambda r: SEV_ORDER.get(r.severity, 3))
    return merged


def finalize(stmt: Stmt) -> None:
    """Confidence, review status and effort estimate (assumptions are documented in the report)."""
    from app.flows.oracle_pg.models import PLSQL_BASELINE_MIN, TIER_BASELINE_MIN

    stmt.baseline_min = PLSQL_BASELINE_MIN if stmt.kind == "plsql" else TIER_BASELINE_MIN[stmt.tier]
    if stmt.status == "portable":
        stmt.confidence, stmt.effort_min, stmt.baseline_min = 0.98, 0, 0
        return
    v = stmt.validation.get("status")
    if v == "ok":
        base = 0.95 if stmt.method == "rules" else 0.8
    elif v == "inconclusive":
        base = 0.8 if stmt.method == "rules" else 0.68
    elif v == "skipped":
        base = 0.55
    else:
        base = 0.15
    if stmt.meta.get("syntax_only_target"):
        base = min(base, 0.75)  # nothing was executed on a target database, so never "auto"
    for r in stmt.risks:
        base -= {"high": 0.22, "medium": 0.08, "low": 0.02}.get(r.severity, 0)
    if stmt.residual and v != "ok":
        base = min(base, 0.3)
    stmt.confidence = round(max(0.05, min(0.99, base)), 2)
    if stmt.confidence >= 0.8:
        stmt.status, stmt.effort_min = "auto", 5
    elif stmt.confidence >= 0.5:
        stmt.status = "review"
        stmt.effort_min = {"trivial": 15, "moderate": 25, "hard": 45}[stmt.tier]
    else:
        stmt.status = "manual"
        stmt.effort_min = int(stmt.baseline_min * 0.8)
    if stmt.kind == "plsql" and stmt.status == "auto":
        stmt.status, stmt.effort_min = "review", 45  # PL/SQL always gets a human review
