import pytest

from app.flows.oracle_pg.extract import discover
from app.flows.oracle_pg.rules import convert_ddl, convert_query, schema_from_ddl, SchemaInfo, tokenize_placeholders, restore_placeholders


def _schema(sample_root):
    stmts, _, _ = discover(sample_root, lambda *a, **k: None, 500)
    return schema_from_ddl([s.oracle_sql for s in stmts if s.kind == "ddl"])


def test_discovery_finds_all_kinds(sample_root):
    stmts, findings, stats = discover(sample_root, lambda *a, **k: None, 500)
    kinds = {s.kind for s in stmts}
    assert {"jdbc", "mybatis", "jpa_native", "jpql", "plsql", "ddl", "jdbc_call"} <= kinds
    assert len(stmts) >= 40
    labels = {s.label for s in stmts}
    assert "EmployeeDao.ORG_TREE" in labels
    assert "CustomerMapper.pageCustomers" in labels
    # spec + body of the package are merged into one unit
    assert sum(1 for s in stmts if s.kind == "plsql") == 1
    cats = {f.category for f in findings}
    assert any("injection" in c.lower() for c in cats)  # planted comment in ReportDao
    assert any("Oracle JDBC driver" in c for c in cats)
    assert any("Hibernate Oracle dialect" in c for c in cats)
    assert any("Hard-coded credential" in c for c in cats)


def test_jpql_is_not_treated_as_native(sample_root):
    stmts, _, _ = discover(sample_root, lambda *a, **k: None, 500)
    by = {s.label: s for s in stmts}
    assert by["ProductRepository.findByCategorySorted"].kind == "jpql"
    assert by["ProductRepository.findLowStock"].kind == "jpa_native"


def test_placeholder_roundtrip():
    sql = "SELECT 1 FROM t WHERE a = ? AND b = #{x} AND c = :name AND d = '?:y' AND e::int = 1"
    tok, m = tokenize_placeholders(sql)
    assert "?" not in tok.replace("'?:y'", "")
    assert restore_placeholders(tok, m) == sql


@pytest.mark.parametrize("oracle,needles,absent", [
    ("SELECT NVL(a, 0), DECODE(b, 'x', 1, 2) FROM t", ["COALESCE", "CASE WHEN"], ["NVL", "DECODE"]),
    ("SELECT * FROM t WHERE ROWNUM <= 10", ["LIMIT 10"], ["ROWNUM"]),
    ("SELECT seq_a.NEXTVAL FROM DUAL", ["nextval('seq_a')"], ["DUAL", "seq_a.NEXTVAL"]),
    ("SELECT a.x FROM a, b WHERE a.id = b.id(+)", ["LEFT JOIN"], ["(+)"]),
    ("SELECT a FROM t MINUS SELECT a FROM u", ["EXCEPT"], ["MINUS"]),
    ("SELECT * FROM t WHERE d > SYSDATE - 7", ["LOCALTIMESTAMP(0)", "INTERVAL"], ["SYSDATE"]),
])
def test_rules_rewrite(oracle, needles, absent):
    r = convert_query(oracle, SchemaInfo(date_columns={"d"}))
    assert r.error is None and r.pg_sql
    low = r.pg_sql.lower()
    for n in needles:
        assert n.lower() in low
    for a in absent:
        assert a.lower() not in low
    assert not r.residual


def test_paging_pattern_becomes_limit_offset():
    sql = ("SELECT * FROM (SELECT a.*, ROWNUM AS RN FROM (SELECT id FROM t ORDER BY id) a WHERE ROWNUM <= :e) WHERE RN > :s")
    r = convert_query(sql, SchemaInfo())
    assert "OFFSET :s" in r.pg_sql and "LIMIT" in r.pg_sql and not r.residual
    assert "rownum_paging" in r.flags


def test_hard_constructs_are_escalated_not_faked():
    for sql in [
        "SELECT LEVEL FROM e START WITH m IS NULL CONNECT BY PRIOR id = m",
        "SELECT MAX(n) KEEP (DENSE_RANK FIRST ORDER BY s DESC) FROM e GROUP BY d",
        "SELECT * FROM (SELECT c, q, r FROM t) PIVOT (SUM(r) FOR q IN ('1' AS q1))",
    ]:
        r = convert_query(sql, SchemaInfo())
        assert r.residual, sql  # must be flagged for the LLM, never silently accepted


def test_rownum_with_order_by_is_flagged():
    r = convert_query("SELECT c, SUM(a) FROM o WHERE ROWNUM <= 5 GROUP BY c ORDER BY 2 DESC", SchemaInfo())
    assert "rownum_before_order" in r.flags


def test_ddl_types():
    r = convert_ddl("CREATE TABLE t (id NUMBER(10) PRIMARY KEY, q NUMBER(6), p NUMBER(10,2), c DATE DEFAULT SYSDATE, n CLOB, v VARCHAR2(10))")
    out = r.pg_sql.upper()
    assert "BIGINT" in out and "INT" in out and "DECIMAL(10, 2)" in out.replace("NUMERIC", "DECIMAL")
    assert "TIMESTAMP(0)" in out and "TEXT" in out and "VARCHAR2" not in out and "SYSDATE" not in out


def test_sequence_ddl():
    r = convert_ddl("CREATE SEQUENCE s START WITH 5 INCREMENT BY 1 NOCACHE")
    assert "NOCACHE" not in r.pg_sql.upper()


def test_rules_validate_on_postgres(sample_root, sandbox):
    stmts, _, _ = discover(sample_root, lambda *a, **k: None, 500)
    ddl = [s for s in stmts if s.kind == "ddl"]
    schema = schema_from_ddl([s.oracle_sql for s in ddl])
    from app.flows.oracle_pg.flow import _order_ddl
    from app.flows.oracle_pg.rules import convert_rules
    for s in _order_ddl(ddl):
        r = convert_rules(s, schema)
        ok, err = sandbox.apply_ddl(r.pg_sql)
        assert ok, (s.label, err)
    good = bad = 0
    for s in stmts:
        if s.kind in ("ddl", "plsql", "jpql", "jdbc_call"):
            continue
        r = convert_rules(s, schema)
        if r.residual or r.error:
            continue  # escalated to the LLM
        status, err = sandbox.validate_query(r.pg_sql)
        assert status in ("ok", "inconclusive"), (s.label, err, r.pg_sql)
        good += 1
    assert good >= 22
