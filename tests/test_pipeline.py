import uuid
from pathlib import Path

from app.core.events import Run
from app.core.registry import FLOWS, RunContext
from app.flows.oracle_pg.models import Stmt
from app.flows.oracle_pg.rules import SchemaInfo
from app.flows.oracle_pg.stmt_graph import StmtPipeline
import app.flows.oracle_pg.flow  # noqa: F401  registers flows
from tests.conftest import FakeLLM
from tests.golden_conversions import answers


def _ctx(tmp_path, llm, inputs=None):
    run = Run("oracle-java-migration")
    return RunContext(run=run, inputs=inputs or {"source": "sample"}, llm=llm, workdir=tmp_path)


def test_full_flow_with_fake_llm(pg_dsn, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_dsn)
    llm = FakeLLM(answers=answers())
    rep = FLOWS["oracle-java-migration"].runner(_ctx(tmp_path, llm))
    s = rep["summary"]
    assert s["validation"].get("failed", 0) == 0, [x["label"] for x in rep["statements"] if x["validation"]["status"] == "failed"]
    assert s["by_method"].get("rules+llm", 0) >= 3 and s["by_method"].get("llm", 0) == 1
    by = {x["label"]: x for x in rep["statements"]}
    # the call to the converted package validates because PL/pgSQL conversion registered it
    assert by["OrderDao.shipOrder"]["validation"]["status"] == "ok"
    assert by["EmployeeDao.ORG_TREE"]["method"] == "rules+llm"
    # semantic risks that a green plan cannot show
    cats = {r["category"] for x in rep["statements"] for r in x["risks"]}
    assert "Empty string vs NULL" in cats and "ROWNUM applied before ORDER BY / GROUP BY" in cats
    assert rep["executive_summary"] == "fake summary"


def test_repair_loop_feeds_postgres_error_back(sandbox):
    calls = {"n": 0}

    def flaky(user):
        calls["n"] += 1
        if "<postgres_error>" in user:
            return {"postgres_sql": "SELECT dept AS d FROM employees_x_unused", "explanation": "x", "needs_manual_review": False}
        return {"postgres_sql": "SELECT FROM WHERE", "explanation": "first try", "needs_manual_review": False}

    llm = FakeLLM(answers={"KEEP (DENSE_RANK": flaky})
    pipe = StmtPipeline(llm=llm, sandbox=sandbox, schema=SchemaInfo(), emit=lambda *a, **k: None, max_repairs=2)
    s = Stmt(id="S1", kind="jdbc", file="x", line=1, label="t", oracle_sql="SELECT MAX(n) KEEP (DENSE_RANK FIRST ORDER BY s) FROM e GROUP BY d")
    pipe.run(s)
    assert s.attempts == 3  # initial + 2 repairs, then stops
    assert s.validation["status"] == "failed"
    assert any("<postgres_error>" in c[2] for c in llm.calls[1:])


def test_output_guard_blocks_dangerous_model_output(sandbox):
    evil = {"postgres_sql": "SELECT pg_read_file('/etc/passwd')", "explanation": "", "needs_manual_review": False}
    llm = FakeLLM(answers={"KEEP (DENSE_RANK": evil})
    pipe = StmtPipeline(llm=llm, sandbox=sandbox, schema=SchemaInfo(), emit=lambda *a, **k: None, max_repairs=2)
    s = Stmt(id="S1", kind="jdbc", file="x", line=1, label="t", oracle_sql="SELECT MAX(n) KEEP (DENSE_RANK FIRST ORDER BY s) FROM e GROUP BY d")
    pipe.run(s)
    assert s.validation["status"] == "failed" and "blocked" in s.validation["error"]


def test_llm_changing_bind_parameters_is_rejected(sandbox):
    bad = {"postgres_sql": "SELECT 1", "explanation": "", "needs_manual_review": False}
    llm = FakeLLM(answers={"KEEP (DENSE_RANK": bad})
    pipe = StmtPipeline(llm=llm, sandbox=sandbox, schema=SchemaInfo(), emit=lambda *a, **k: None, max_repairs=0)
    s = Stmt(id="S1", kind="jdbc", file="x", line=1, label="t",
             oracle_sql="SELECT MAX(n) KEEP (DENSE_RANK FIRST ORDER BY s) FROM e WHERE a = ? GROUP BY d")
    pipe.run(s)
    assert s.validation["status"] == "failed" and "bind parameters" in s.validation["error"]


def test_pivot_never_passes_silently(sandbox):
    """Without an LLM the dropped PIVOT must end up failed/manual, not 'ok'."""
    llm = FakeLLM()
    llm.available = False
    pipe = StmtPipeline(llm=llm, sandbox=sandbox, schema=SchemaInfo(), emit=lambda *a, **k: None, max_repairs=2)
    s = Stmt(id="S1", kind="jdbc", file="x", line=1, label="t",
             oracle_sql="SELECT * FROM (SELECT 'a' AS c, '1' AS q, 2 AS r) PIVOT (SUM(r) FOR q IN ('1' AS q1))")
    pipe.run(s)
    assert s.validation["status"] == "failed"


def test_snippet_flow_rules_only(pg_dsn, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_dsn)
    llm = FakeLLM()
    llm.available = False
    ctx = _ctx(tmp_path, llm, {"sql": "SELECT order_id FROM orders WHERE notes IS NULL OR notes = ''"})
    rep = FLOWS["sql-snippet-converter"].runner(ctx)
    st = rep["statements"][0]
    assert st["validation"]["status"] == "ok"
    assert any(r["category"] == "Empty string vs NULL" and r["severity"] == "high" for r in st["risks"])


def test_runs_without_any_database(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    llm = FakeLLM()
    llm.available = False
    rep = FLOWS["oracle-java-migration"].runner(_ctx(tmp_path, llm))
    assert rep["meta"]["sandbox"]["mode"] == "syntax-only"
    assert rep["summary"]["statements"] >= 40


# ------------------------------------------------------------------ Code Reader agent
def _hr_ctx(tmp_path, llm):
    run = Run("oracle-java-migration")
    return RunContext(run=run, inputs={"source": "sample2"}, llm=llm, workdir=tmp_path)


def test_reader_finds_gaps_without_false_positives():
    from app.config import settings
    from app.flows.oracle_pg import extract, reader
    for name, expect_gaps in [("acme-orders-oracle", False), ("hr-reports-oracle", True)]:
        root = settings.sample_app_dir.parent / name
        stmts, _, _ = extract.discover(root, lambda *a, **k: None, 500)
        files = sorted(p for p in root.rglob("*") if p.is_file())
        assert bool(reader.find_gaps(root, files, stmts)) == expect_gaps, name


def test_reader_without_llm_reports_findings_not_guesses(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    llm = FakeLLM()
    llm.available = False
    rep = FLOWS["oracle-java-migration"].runner(_hr_ctx(tmp_path, llm))
    assert any(f["category"] == "SQL not extracted by the Code Reader" for f in rep["findings"])
    assert not any(s["meta"].get("reader") for s in rep["statements"])
    prof = rep["meta"]["files"]["profile"]
    assert {f["name"] for f in prof["frameworks"]} >= {"Plain JDBC"}


def test_reader_reconstructs_with_llm_and_rejects_invented_tables(pg_dsn, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_dsn)
    good = {"oracle_sql": "SELECT emp_id, full_name, salary FROM employees e WHERE e.full_name IS NOT NULL AND e.department = ? "
                          "AND e.salary >= ? AND ROWNUM <= 100 ORDER BY __DYN_sortColumn__",
            "line": 17, "method": "search", "kind": "jdbc", "dynamic": True, "dynamic_parts": ["sortColumn"],
            "note": "optional filters appended with StringBuilder"}
    invented = {"oracle_sql": "SELECT secret_col FROM payroll_vault WHERE vault_key = ?", "line": 1, "method": "x", "dynamic": False,
                "note": "made up"}
    llm = FakeLLM(answers={"EmployeeSearchDao": {"statements": [good, invented]}})
    rep = FLOWS["oracle-java-migration"].runner(_hr_ctx(tmp_path, llm))
    read = [s for s in rep["statements"] if s["meta"].get("reader") == "llm"]
    assert len(read) == 1 and read[0]["label"] == "EmployeeSearchDao.search"
    assert read[0]["validation"]["status"] in ("ok", "inconclusive")
    assert any(r["category"] == "Reconstructed from Java code by Claude" for r in read[0]["risks"])
    assert rep["meta"]["files"]["reader"]["rejected"] == 1
    assert not any("payroll_vault" in s["oracle_sql"] for s in rep["statements"])
