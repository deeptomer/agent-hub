"""Report assembly (JSON / Markdown / HTML) for a migration run."""
from __future__ import annotations

import html
import time
from collections import Counter
from typing import Any

from app.core.security import Finding
from app.flows.oracle_pg.models import PLSQL_BASELINE_MIN, TIER_BASELINE_MIN, Stmt

ASSUMPTIONS = {
    "baseline_minutes_per_statement": {**TIER_BASELINE_MIN, "plsql_unit": PLSQL_BASELINE_MIN},
    "assisted_minutes": {"auto": 5, "review": "15-45 by tier", "manual": "80% of baseline"},
    "note": "Planning assumptions for a typical engineer reading, rewriting and testing each statement by hand. "
            "Replace them with your own team's numbers.",
}

CHECKLIST_BASE = [
    "Provision PostgreSQL 15+ (MERGE needs 15) and deploy compat_shims.sql if any converted statement uses it.",
    "Swap the JDBC driver, URL and Hibernate dialect; remove Oracle-specific imports and error-code handling.",
    "Migrate data (ora2pg, pgloader or AWS DMS), then advance every sequence with setval() past the migrated maximum.",
    "PostgreSQL aborts the whole transaction on any error: Java code that catches SQLException and carries on needs "
    "savepoints or a rollback.",
    "Re-tune performance: ANALYZE, review the indexes, and replace dropped optimizer hints with measured fixes.",
    "Run a dual-database regression suite (same inputs against Oracle and PostgreSQL) before cut-over.",
]


def build_report(*, run_id: str, source_name: str, stmts: list[Stmt], findings: list[Finding], stats: dict[str, Any],
                 sandbox: Any, llm: Any, started: float, executive_summary: str | None = None) -> dict[str, Any]:
    n = len(stmts)
    by_status = Counter(s.status for s in stmts)
    by_method = Counter(s.method for s in stmts)
    by_val = Counter(s.validation.get("status", "pending") for s in stmts)
    by_kind = Counter(s.kind for s in stmts)
    by_tier = Counter(s.tier for s in stmts)
    risk_counts = Counter(r.severity for s in stmts for r in s.risks)
    construct_counts = Counter(c for s in stmts for c in s.constructs)
    baseline = sum(s.baseline_min for s in stmts)
    assisted = sum(s.effort_min for s in stmts)
    saved = max(baseline - assisted, 0)
    conf = [s.confidence for s in stmts if s.status != "portable"]
    summary = {
        "statements": n,
        "by_kind": dict(by_kind), "by_tier": dict(by_tier), "by_status": dict(by_status),
        "by_method": dict(by_method), "validation": dict(by_val), "risks": dict(risk_counts),
        "avg_confidence": round(sum(conf) / len(conf), 2) if conf else 0.0,
        "top_constructs": construct_counts.most_common(12),
        "effort": {
            "baseline_hours": round(baseline / 60, 1), "assisted_hours": round(assisted / 60, 1),
            "saved_hours": round(saved / 60, 1), "saved_pct": round(100 * saved / baseline) if baseline else 0,
            "assumptions": ASSUMPTIONS,
        },
        "auto_rate_pct": round(100 * (by_status.get("auto", 0) + by_status.get("portable", 0)) / n) if n else 0,
    }
    checklist = list(CHECKLIST_BASE)
    for f in findings:
        if f.category.startswith("App change needed"):
            line = f"{f.category.replace('App change needed: ', '')} ({f.file}:{f.line}): {f.detail}"
            if line not in checklist:
                checklist.append(line)
    if executive_summary is None and n == 1:
        s0 = stmts[0]
        executive_summary = (
            f"The statement was converted by {s0.method.replace('+', ' and ')} and its validation result is "
            f"'{s0.validation.get('status')}'. Confidence {s0.confidence}, status '{s0.status}', "
            f"{len(s0.risks)} behaviour difference(s) to check.")
    if executive_summary is None:
        executive_summary = (
            f"Analysed {n} SQL statements. {summary['auto_rate_pct']}% were converted and validated with little or no manual work; "
            f"{by_status.get('review', 0)} need review and {by_status.get('manual', 0)} need manual work. "
            f"{risk_counts.get('high', 0)} high-severity semantic risks were flagged. Estimated effort: "
            f"{summary['effort']['assisted_hours']} h with the tool vs {summary['effort']['baseline_hours']} h manually.")
    return {
        "meta": {"run_id": run_id, "source": source_name, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                 "duration_s": round(time.time() - started, 1),
                 "sandbox": {"mode": sandbox.mode, "version": sandbox.version, "error": sandbox.error},
                 "llm": {"available": llm.available, "usage": llm.usage_summary(), "last_error": llm.last_error},
                 "files": stats},
        "summary": summary,
        "executive_summary": executive_summary,
        "statements": [s.to_dict() for s in stmts],
        "findings": [f.to_dict() for f in findings],
        "checklist": checklist,
    }


# ------------------------------------------------------------------------------------------- renderers
def to_markdown(rep: dict[str, Any]) -> str:
    m, s = rep["meta"], rep["summary"]
    out = [f"# Oracle to PostgreSQL migration assessment", "", f"Source: **{m['source']}**  |  Run {m['run_id']}  |  {m['generated_at']}", "",
           "## Executive summary", "", rep["executive_summary"], "",
           "## Numbers", "",
           f"- Statements analysed: **{s['statements']}**",
           f"- Auto-converted or portable: **{s['auto_rate_pct']}%** (average confidence {s['avg_confidence']})",
           f"- Status: {', '.join(f'{k} {v}' for k, v in s['by_status'].items())}",
           f"- Validation ({m['sandbox']['mode']}): {', '.join(f'{k} {v}' for k, v in s['validation'].items())}",
           f"- Risks: {', '.join(f'{k} {v}' for k, v in s['risks'].items()) or 'none'}",
           f"- Effort: {s['effort']['assisted_hours']} h with the tool vs {s['effort']['baseline_hours']} h manual "
           f"({s['effort']['saved_pct']}% saved, planning assumptions)", ""]
    if rep["findings"]:
        out += ["## Security and application findings", ""]
        for f in rep["findings"]:
            out.append(f"- **{f['severity'].upper()}** {f['category']} - `{f['file']}:{f['line']}` - {f['detail']}")
        out.append("")
    out += ["## Migration checklist (non-SQL work)", ""] + [f"- {c}" for c in rep["checklist"]] + ["", "## Statements", ""]
    for st in rep["statements"]:
        out += [f"### {st['id']} {st['label']}  ({st['kind']}, {st['status']}, confidence {st['confidence']})", "",
                f"`{st['file']}:{st['line']}`  |  method: {st['method']}  |  validation: {st['validation']['status']}", ""]
        out += ["Oracle:", "```sql", st["oracle_sql"], "```", "PostgreSQL:", "```sql", st["pg_sql"] or "-- not converted", "```"]
        if st["validation"].get("error"):
            out.append(f"Validator: {st['validation']['error']}")
        for r in st["risks"]:
            out.append(f"- Risk ({r['severity']}) **{r['category']}**: {r['message']} {('Fix: ' + r['suggestion']) if r['suggestion'] else ''}")
        out.append("")
    return "\n".join(out)


def to_html(rep: dict[str, Any]) -> str:
    e = html.escape
    m, s = rep["meta"], rep["summary"]
    rows = []
    for st in rep["statements"]:
        risks = "".join(f"<li><b>{e(r['severity'])}</b> {e(r['category'])}: {e(r['message'])}</li>" for r in st["risks"])
        rows.append(
            f"<details><summary><b>{e(st['id'])}</b> {e(st['label'])} <span class='tag {e(st['status'])}'>{e(st['status'])}</span> "
            f"<span class='muted'>{e(st['kind'])} | confidence {st['confidence']}</span></summary>"
            f"<div class='cols'><div><h4>Oracle</h4><pre>{e(st['oracle_sql'])}</pre></div>"
            f"<div><h4>PostgreSQL</h4><pre>{e(st['pg_sql'] or '-- not converted')}</pre></div></div>"
            f"<p class='muted'>{e(st['file'])}:{st['line']} | {e(st['method'])} | validation {e(st['validation']['status'])} "
            f"{e(st['validation'].get('error') or '')}</p><ul>{risks}</ul></details>")
    fnd = "".join(f"<li><b>{e(f['severity'])}</b> {e(f['category'])} <code>{e(f['file'])}:{f['line']}</code> {e(f['detail'])}</li>"
                  for f in rep["findings"])
    chk = "".join(f"<li>{e(c)}</li>" for c in rep["checklist"])
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>Migration assessment</title><style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f24}}
pre{{background:#f4f6f8;padding:.7rem;overflow:auto;border-radius:6px;font-size:12.5px;white-space:pre-wrap}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:1rem}}details{{border:1px solid #d8dee4;border-radius:8px;margin:.5rem 0;padding:.5rem .8rem}}
.tag{{padding:1px 8px;border-radius:10px;font-size:12px;background:#e8eef4}}.auto,.portable{{background:#d9f2e3}}.review{{background:#fff1cc}}.manual{{background:#fddcdc}}
.muted{{color:#667}}h1,h2{{margin-top:1.6rem}}</style></head><body>
<h1>Oracle to PostgreSQL migration assessment</h1><p class="muted">{e(m['source'])} | run {e(m['run_id'])} | {e(m['generated_at'])}</p>
<h2>Executive summary</h2><p>{e(rep['executive_summary'])}</p>
<p><b>{s['statements']}</b> statements | auto/portable <b>{s['auto_rate_pct']}%</b> | avg confidence <b>{s['avg_confidence']}</b> |
effort <b>{s['effort']['assisted_hours']} h</b> vs <b>{s['effort']['baseline_hours']} h</b> manual</p>
<h2>Security and application findings</h2><ul>{fnd or '<li>none</li>'}</ul>
<h2>Migration checklist</h2><ul>{chk}</ul><h2>Statements</h2>{''.join(rows)}</body></html>"""
