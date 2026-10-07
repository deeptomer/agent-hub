"""Deterministic Oracle -> PostgreSQL conversion (sqlglot + our own AST rewrites).

This is the "cheap and reliable" half of the hybrid: it handles the common constructs exactly the same way every
time, reports what it changed, and - just as important - detects what it could NOT convert (or silently dropped) so
the LLM only sees the hard cases."""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.transforms import eliminate_join_marks

from app.flows.oracle_pg.constructs import mask_strings
from app.flows.oracle_pg.models import Stmt

# ---------------------------------------------------------------------------- capture sqlglot warnings per thread
_tls = threading.local()


class _Capture(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        buf = getattr(_tls, "buf", None)
        if buf is not None:
            buf.append(record.getMessage())


_lg = logging.getLogger("sqlglot")
_lg.addHandler(_Capture())
_lg.propagate = False

FROM_KEY = "from_" if "from_" in exp.Select.arg_types else "from"


# ---------------------------------------------------------------------------- schema knowledge
@dataclass
class SchemaInfo:
    date_columns: set[str] = field(default_factory=set)  # lower-case column names typed DATE/TIMESTAMP in Oracle
    tables: dict[str, dict[str, str]] = field(default_factory=dict)  # table -> column -> pg type (summary text)
    pg_types: dict[str, dict[str, str]] = field(default_factory=dict)  # table -> column -> PostgreSQL type for casts

    def summary(self, limit: int = 3500) -> str:
        lines = []
        for t, cols in self.tables.items():
            lines.append(f"{t}({', '.join(f'{c} {ty}' for c, ty in cols.items())})")
        s = "\n".join(lines)
        return s if len(s) <= limit else s[:limit] + "\n..."


@dataclass
class RuleResult:
    pg_sql: str | None = None
    notes: list[str] = field(default_factory=list)
    residual: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    shims: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------- placeholders
_STR_SPLIT = re.compile(r"('(?:[^']|'')*')")
_PH_RESTORE = re.compile(r"__ph(\d+)__", re.I)


def tokenize_placeholders(sql: str) -> tuple[str, dict[int, str]]:
    """Replace ?, #{x}, ${x}, :name with identifier-like tokens so sqlglot can parse them; keep a map to restore."""
    mapping: dict[int, str] = {}

    def make(orig: str) -> str:
        n = len(mapping) + 1
        mapping[n] = orig
        return f"__ph{n}__"

    out = []
    for i, seg in enumerate(_STR_SPLIT.split(sql)):
        if i % 2 == 1:
            out.append(seg)
            continue
        seg = re.sub(r"#\{[^}]*\}", lambda m: make(m.group(0)), seg)
        seg = re.sub(r"\$\{[^}]*\}", lambda m: make(m.group(0)), seg)
        seg = re.sub(r"(?<![:\w]):([A-Za-z_]\w*)", lambda m: make(m.group(0)), seg)
        seg = re.sub(r"\?", lambda m: make("?"), seg)
        out.append(seg)
    return "".join(out), mapping


def restore_placeholders(sql: str, mapping: dict[int, str]) -> str:
    return _PH_RESTORE.sub(lambda m: mapping.get(int(m.group(1)), m.group(0)), sql)


# ---------------------------------------------------------------------------- helpers
_UNIT = {"DD": "day", "DDD": "day", "J": "day", "MM": "month", "MON": "month", "MONTH": "month", "RM": "month",
         "YYYY": "year", "YEAR": "year", "YY": "year", "Y": "year", "Q": "quarter", "HH": "hour", "HH12": "hour",
         "HH24": "hour", "MI": "minute", "D": "week", "DAY": "week", "DY": "week", "IW": "week"}

_DATE_FUNCS = {"ADD_MONTHS", "TO_DATE", "LAST_DAY", "TO_TIMESTAMP", "NEXT_DAY", "SYSDATE"}
_DATE_CLASS_NAMES = {"Systimestamp", "CurrentTimestamp", "CurrentDate", "DateTrunc", "TimestampTrunc", "TsOrDsToDate", "StrToDate",
                     "StrToTime", "CurrentDatetime", "Date", "TimeStrToTime"}


def _is_dateish(n: exp.Expression, date_cols: set[str]) -> bool:
    if isinstance(n, exp.Paren):
        return _is_dateish(n.this, date_cols)
    if type(n).__name__ in _DATE_CLASS_NAMES:
        return True
    if isinstance(n, exp.Var) and n.name.upper() in ("LOCALTIMESTAMP(0)", "CURRENT_TIMESTAMP"):
        return True
    if isinstance(n, exp.Anonymous) and n.name.upper() in _DATE_FUNCS:
        return True
    if isinstance(n, exp.Column) and not n.name.startswith("__ph") and n.name.lower() in date_cols:
        return True
    if isinstance(n, (exp.Add, exp.Sub)):
        return _is_dateish(n.this, date_cols) and not _is_dateish(n.expression, date_cols)
    return False


def _is_numberish(n: exp.Expression) -> bool:
    if isinstance(n, exp.Literal):
        return not n.is_string
    if isinstance(n, exp.Interval):
        return False
    if isinstance(n, (exp.Mul, exp.Div, exp.Add, exp.Sub, exp.Neg)):
        return True
    if isinstance(n, exp.Paren):
        return _is_numberish(n.this)
    if isinstance(n, exp.Column):
        return True  # placeholder token or unknown column: assume number of days
    return False


# ---------------------------------------------------------------------------- AST passes
def _pass_sequences(tree: exp.Expression, notes: list[str]) -> exp.Expression:
    def fn(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Column) and node.name.upper() in ("NEXTVAL", "CURRVAL") and node.table:
            seq = node.table.lower()
            func = "nextval" if node.name.upper() == "NEXTVAL" else "currval"
            notes.append(f"{node.table}.{node.name.upper()} -> {func}('{seq}')")
            return exp.Anonymous(this=func, expressions=[exp.Literal.string(seq)])
        return node

    return tree.transform(fn)


def _pass_sysdate(tree: exp.Expression, notes: list[str]) -> exp.Expression:
    def fn(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.CurrentTimestamp) and node.args.get("sysdate"):
            notes.append("SYSDATE -> LOCALTIMESTAMP(0) (Oracle DATE has a time part and no time zone)")
            return exp.Var(this="LOCALTIMESTAMP(0)")
        if type(node).__name__ == "Systimestamp" or (
                isinstance(node, (exp.Anonymous, exp.Column)) and node.name.upper() == "SYSTIMESTAMP" and not node.table):
            notes.append("SYSTIMESTAMP -> CURRENT_TIMESTAMP")
            return exp.Var(this="CURRENT_TIMESTAMP")
        return node

    return tree.transform(fn)


def _pass_trunc(tree: exp.Expression, notes: list[str], date_cols: set[str], residual: list[str]) -> exp.Expression:
    def unit_of(lit: exp.Expression) -> str | None:
        if isinstance(lit, exp.Literal) and lit.is_string:
            return _UNIT.get(lit.name.upper())
        return None

    def fn(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.DateTrunc):
            unit = node.args.get("unit")
            mapped = unit_of(unit) if unit is not None else None
            if mapped:
                notes.append(f"TRUNC(date, '{unit.name}') -> DATE_TRUNC('{mapped}', ...)")
                return exp.DateTrunc(this=node.this, unit=exp.Literal.string(mapped))
            if unit is not None and isinstance(unit, exp.Literal) and unit.name.lower() in (
                    "day", "month", "year", "quarter", "hour", "minute", "week"):
                return node
            residual.append(f"TRUNC unit {unit.sql() if unit is not None else '?'} has no direct mapping")
            return node
        if isinstance(node, exp.Anonymous) and node.name.upper() == "TRUNC":
            args = node.expressions
            if len(args) == 1 and _is_dateish(args[0], date_cols):
                notes.append("TRUNC(date) -> DATE_TRUNC('day', ...)")
                return exp.DateTrunc(this=args[0], unit=exp.Literal.string("day"))
            if len(args) == 2 and isinstance(args[1], exp.Literal) and args[1].is_string:
                mapped = unit_of(args[1])
                if mapped:
                    notes.append(f"TRUNC(date, '{args[1].name}') -> DATE_TRUNC('{mapped}', ...)")
                    return exp.DateTrunc(this=args[0], unit=exp.Literal.string(mapped))
        return node

    return tree.transform(fn)


def _pass_date_arith(tree: exp.Expression, notes: list[str], date_cols: set[str]) -> exp.Expression:
    day = lambda: exp.Interval(this=exp.Literal.string("1 day"))  # noqa: E731

    def fn(node: exp.Expression) -> exp.Expression:
        if not isinstance(node, (exp.Add, exp.Sub)):
            return node
        left, right = node.this, node.expression
        if _is_dateish(left, date_cols) and _is_dateish(right, date_cols) and isinstance(node, exp.Sub):
            notes.append("date - date -> EXTRACT(EPOCH ...)/86400 (Oracle returns days as a number)")
            return exp.Div(this=exp.Extract(this=exp.Var(this="EPOCH"), expression=exp.Paren(this=node.copy())),
                           expression=exp.Literal.number(86400))
        if _is_dateish(left, date_cols) and not _is_dateish(right, date_cols) and _is_numberish(right):
            notes.append("date +/- number-of-days -> date +/- n * INTERVAL '1 day'")
            r = exp.Paren(this=right) if isinstance(right, (exp.Add, exp.Sub)) else right
            return type(node)(this=left, expression=exp.Mul(this=r, expression=day()))
        return node

    return tree.transform(fn)


def _conjuncts(e: exp.Expression) -> list[exp.Expression]:
    if isinstance(e, exp.And):
        return _conjuncts(e.this) + _conjuncts(e.expression)
    if isinstance(e, exp.Paren) and isinstance(e.this, exp.And):
        return _conjuncts(e.this)
    return [e]


def _is_rownum(e: exp.Expression) -> bool:
    return isinstance(e, exp.Column) and e.name.upper() == "ROWNUM" and not e.table


def _limit_from_pred(p: exp.Expression) -> exp.Expression | None:
    if isinstance(p, exp.LTE) and _is_rownum(p.this):
        return p.expression.copy()
    if isinstance(p, exp.LT) and _is_rownum(p.this):
        v = p.expression
        if isinstance(v, exp.Literal) and not v.is_string:
            return exp.Literal.number(max(int(v.name) - 1, 0))
        return exp.Paren(this=exp.Sub(this=v.copy(), expression=exp.Literal.number(1)))
    if isinstance(p, exp.EQ) and _is_rownum(p.this) and isinstance(p.expression, exp.Literal) and p.expression.name == "1":
        return exp.Literal.number(1)
    return None


def _pass_rownum(tree: exp.Expression, notes: list[str], flags: list[str]) -> exp.Expression:
    def rewrite(node: exp.Expression) -> exp.Expression:
        where = node.args.get("where") if isinstance(node, (exp.Select, exp.Delete)) else None
        if where is None:
            return node
        preds = _conjuncts(where.this)
        limit_expr = None
        rest = []
        for p in preds:
            lim = _limit_from_pred(p)
            if lim is not None and limit_expr is None:
                limit_expr = lim
            else:
                rest.append(p)
        if limit_expr is None:
            return node
        new_where = exp.and_(*rest) if rest else None
        if isinstance(node, exp.Select):
            if node.args.get("limit") is not None:
                return node
            if node.args.get("order") or node.args.get("group") or node.args.get("distinct"):
                flags.append("rownum_before_order")
            node.set("where", exp.Where(this=new_where) if new_where is not None else None)
            node.limit(limit_expr, copy=False)
            notes.append("ROWNUM predicate -> LIMIT")
            return node
        if isinstance(node, exp.Delete):
            tbl = node.this
            sub = exp.Select().select("ctid").from_(tbl.copy())
            if new_where is not None:
                sub = sub.where(new_where)
            sub = sub.limit(limit_expr)
            node.set("where", exp.Where(this=exp.In(this=exp.column("ctid"), query=sub.subquery())))
            flags.append("rownum_delete_ctid")
            notes.append("DELETE ... ROWNUM <= n -> DELETE ... WHERE ctid IN (SELECT ctid ... LIMIT n)")
            return node
        return node

    for n in list(tree.find_all(exp.Select, exp.Delete)):
        rewrite(n)
    return tree


def _pass_rownum_paging(tree: exp.Expression, notes: list[str], flags: list[str]) -> exp.Expression:
    """Classic two-level Oracle paging:
         SELECT * FROM (SELECT a.*, ROWNUM RN FROM (<q ORDER BY ..>) a WHERE ROWNUM <= :end) WHERE RN > :start
       becomes SELECT * FROM (<q ORDER BY ..>) a LIMIT (:end - :start) OFFSET :start"""
    for outer in list(tree.find_all(exp.Select)):
        frm = outer.args.get(FROM_KEY)
        if frm is None or not isinstance(frm.this, exp.Subquery) or not isinstance(frm.this.this, exp.Select):
            continue
        mid = frm.this.this
        ow, mw = outer.args.get("where"), mid.args.get("where")
        mid_from = mid.args.get(FROM_KEY)
        if ow is None or mw is None or mid_from is None:
            continue
        rn_name = None
        for e in mid.expressions:
            if isinstance(e, exp.Alias) and _is_rownum(e.this):
                rn_name = e.alias.lower()
        if not rn_name:
            continue
        mid_preds = _conjuncts(mw.this)
        end_expr = _limit_from_pred(mid_preds[0]) if len(mid_preds) == 1 else None
        out_preds = _conjuncts(ow.this)
        if end_expr is None or len(out_preds) != 1:
            continue
        p = out_preds[0]
        if not (isinstance(p, (exp.GT, exp.GTE)) and isinstance(p.this, exp.Column) and p.this.name.lower() == rn_name):
            continue
        if any(isinstance(e, exp.Column) and e.name.lower() == rn_name for e in outer.expressions):
            continue  # caller reads RN itself: leave it to the LLM
        start = p.expression.copy()
        if isinstance(p, exp.GTE):
            start = exp.Sub(this=start, expression=exp.Literal.number(1))
        if isinstance(end_expr, exp.Literal) and isinstance(start, exp.Literal):
            count: exp.Expression = exp.Literal.number(int(end_expr.name) - int(start.name))
        else:
            count = exp.Paren(this=exp.Sub(this=end_expr.copy(), expression=start.copy()))
        outer.set(FROM_KEY, mid_from.copy())
        outer.set("where", None)
        outer.limit(count, copy=False)
        outer.offset(start, copy=False)
        flags.append("rownum_paging")
        notes.append("two-level ROWNUM paging -> LIMIT/OFFSET (the RN column is no longer produced)")
    return tree


def _pass_update_set_qualifiers(tree: exp.Expression, notes: list[str]) -> exp.Expression:
    changed = False
    for upd in tree.find_all(exp.Update):
        for eq in upd.args.get("expressions") or []:
            left = eq.this if isinstance(eq, exp.EQ) else None
            if isinstance(left, exp.Column) and left.table:
                left.set("table", None)
                changed = True
    if changed:
        notes.append("UPDATE ... SET alias.col -> SET col (PostgreSQL does not allow a qualifier there)")
    return tree


def _pass_merge_casts(tree: exp.Expression, notes: list[str], schema: SchemaInfo) -> exp.Expression:
    """MERGE ... USING (SELECT ? AS col ... FROM DUAL): PostgreSQL cannot infer the type of a bare parameter, so cast
    each one to the type of the target column it feeds."""
    if not isinstance(tree, exp.Merge):
        return tree
    target = tree.this
    using = tree.args.get("using")
    if not isinstance(target, exp.Table) or not isinstance(using, exp.Subquery) or not isinstance(using.this, exp.Select):
        return tree
    t_alias = (target.alias or target.name).lower()
    s_alias = (using.alias or "").lower()
    types = schema.pg_types.get(target.name.lower(), {})
    if not types or not s_alias:
        return tree

    def is_src(c: exp.Expression) -> bool:
        return isinstance(c, exp.Column) and c.table.lower() == s_alias

    mapping: dict[str, str] = {}
    on = tree.args.get("on")
    if on is not None:
        for eq in on.find_all(exp.EQ):
            a, b = eq.this, eq.expression
            if is_src(b) and isinstance(a, exp.Column) and a.table.lower() in (t_alias, ""):
                mapping.setdefault(b.name.lower(), a.name.lower())
            elif is_src(a) and isinstance(b, exp.Column) and b.table.lower() in (t_alias, ""):
                mapping.setdefault(a.name.lower(), b.name.lower())
    whens = tree.args.get("whens")
    for w in (whens.expressions if whens is not None else []):
        then = w.args.get("then")
        if isinstance(then, exp.Update):
            for eq in then.args.get("expressions") or []:
                if isinstance(eq, exp.EQ) and is_src(eq.expression) and isinstance(eq.this, exp.Column):
                    mapping.setdefault(eq.expression.name.lower(), eq.this.name.lower())
        elif isinstance(then, exp.Insert):
            cols, vals = then.this, then.args.get("expression")
            if isinstance(cols, exp.Tuple) and isinstance(vals, exp.Tuple):
                for c, v in zip(cols.expressions, vals.expressions):
                    if is_src(v) and isinstance(c, exp.Column):
                        mapping.setdefault(v.name.lower(), c.name.lower())
    cast = 0
    for e in using.this.expressions:
        if isinstance(e, exp.Alias) and isinstance(e.this, exp.Column) and e.this.name.startswith("__ph"):
            tcol = mapping.get(e.alias.lower())
            ty = types.get(tcol) if tcol else None
            if ty:
                e.set("this", exp.Cast(this=e.this, to=exp.DataType.build(ty)))
                cast += 1
    if cast:
        notes.append(f"MERGE: {cast} bind parameter(s) cast to the target column types (PostgreSQL cannot infer them)")
    return tree


def _pass_alias_subqueries(tree: exp.Expression) -> exp.Expression:
    i = 0
    for sq in tree.find_all(exp.Subquery):
        parent = sq.parent
        if isinstance(parent, (exp.From, exp.Join)) and not sq.args.get("alias"):
            i += 1
            sq.set("alias", exp.TableAlias(this=exp.to_identifier(f"t{i}")))
    return tree


def _pass_dual(tree: exp.Expression, notes: list[str]) -> exp.Expression:
    for sel in tree.find_all(exp.Select):
        frm = sel.args.get(FROM_KEY)
        if frm is not None and isinstance(frm.this, exp.Table) and frm.this.name.upper() == "DUAL" and not frm.this.db:
            sel.set(FROM_KEY, None)
            notes.append("FROM DUAL removed")
    return tree


def _pass_join_marks(tree: exp.Expression, notes: list[str]) -> exp.Expression:
    if not any(c.args.get("join_mark") for c in tree.find_all(exp.Column)):
        return tree
    notes.append("(+) outer joins -> ANSI LEFT/RIGHT JOIN")
    for sel in list(tree.find_all(exp.Select)):
        if any(c.args.get("join_mark") for c in sel.find_all(exp.Column)):
            try:
                new = eliminate_join_marks(sel)
                if new is not sel:
                    sel.replace(new)
            except Exception:  # leave to the residual scan / LLM
                pass
    return tree


# ---------------------------------------------------------------------------- residual detection
_RESIDUALS = [
    ("ROWNUM", r"\bROWNUM\b"),
    ("CONNECT BY / START WITH (hierarchical query)", r"\bCONNECT\s+BY\b|\bSTART\s+WITH\b|\bORDER\s+SIBLINGS\b"),
    ("KEEP (DENSE_RANK ...)", r"\bKEEP\s*\("),
    ("sequence .NEXTVAL/.CURRVAL", r"\.(NEXTVAL|CURRVAL)\b"),
    ("FROM DUAL", r"\bFROM\s+DUAL\b"),
    ("SYSDATE/SYSTIMESTAMP", r"\bSYS(DATE|TIMESTAMP)\b"),
    ("MINUS", r"\bMINUS\b"),
    ("PRIOR", r"\bPRIOR\b"),
    ("NVL/NVL2/DECODE", r"\b(NVL2?|DECODE)\s*\("),
    ("(+) outer join", r"\(\s*\+\s*\)"),
    ("Oracle types", r"\b(VARCHAR2|NVARCHAR2|CLOB|BLOB)\b"),
]
_RES_RX = [(label, re.compile(rx, re.I)) for label, rx in _RESIDUALS]

_SHIM_NAMES = ["add_months", "months_between", "last_day", "next_day", "instr", "regexp_like", "to_number", "sys_guid"]


def residual_constructs(pg_sql: str, oracle_sql: str, parser_output: bool = True) -> list[str]:
    """parser_output=False for model-written SQL: a PIVOT that is gone there was rewritten, not dropped by sqlglot."""
    masked = mask_strings(pg_sql)
    out = [label for label, rx in _RES_RX if rx.search(masked)]
    if not parser_output:
        return out
    if re.search(r"\bPIVOT\s*\(", oracle_sql, re.I) and not re.search(r"\bPIVOT\b", pg_sql, re.I):
        out.append("PIVOT was silently dropped by the parser")
    if re.search(r"\bUNPIVOT\s*\(", oracle_sql, re.I) and not re.search(r"\bUNPIVOT\b", pg_sql, re.I):
        out.append("UNPIVOT was silently dropped by the parser")
    return out


def shims_used(pg_sql: str) -> list[str]:
    masked = mask_strings(pg_sql).lower()
    return [n for n in _SHIM_NAMES if re.search(rf"\b{n}\s*\(", masked)]


# ---------------------------------------------------------------------------- DML / query conversion
def convert_query(sql: str, schema: SchemaInfo) -> RuleResult:
    res = RuleResult()
    text = sql.strip().rstrip(";").strip()
    tokenized, mapping = tokenize_placeholders(text)
    _tls.buf = res.warnings
    try:
        tree = sqlglot.parse_one(tokenized, read="oracle")
    except Exception as exc:
        res.error = f"parse error: {str(exc).splitlines()[0][:200]}"
        return res
    finally:
        pass
    try:
        notes, residual = res.notes, res.residual
        tree = _pass_join_marks(tree, notes)
        tree = _pass_sequences(tree, notes)
        tree = _pass_sysdate(tree, notes)
        tree = _pass_trunc(tree, notes, schema.date_columns, residual)
        tree = _pass_date_arith(tree, notes, schema.date_columns)
        tree = _pass_rownum_paging(tree, notes, res.flags)
        tree = _pass_rownum(tree, notes, res.flags)
        tree = _pass_update_set_qualifiers(tree, notes)
        tree = _pass_merge_casts(tree, notes, schema)
        tree = _pass_dual(tree, notes)
        tree = _pass_alias_subqueries(tree)
        out = tree.sql(dialect="postgres", pretty=True)
    except Exception as exc:
        res.error = f"conversion error: {type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
        return res
    finally:
        _tls.buf = None
    out = restore_placeholders(out, mapping)
    res.pg_sql = out
    for w in res.warnings:
        if "Hints are not supported" in w:
            res.notes.append("optimizer hints removed (re-tune with EXPLAIN ANALYZE)")
            res.flags.append("hint_dropped")
        elif "unsupported" in w.lower():
            res.residual.append(f"parser warning: {w[:100]}")
    res.residual += residual_constructs(out, sql)
    res.residual = list(dict.fromkeys(res.residual))
    res.shims = shims_used(out)
    if "DECODE" in sql.upper() and re.search(r"DECODE\s*\([^)]*,\s*NULL\s*,", sql, re.I):
        res.flags.append("decode_null")
    return res


# ---------------------------------------------------------------------------- DDL conversion
_SEQ_MAX = 9223372036854775807


def _pg_type_for_number(dt: exp.DataType) -> exp.DataType | None:
    params = [p for p in dt.expressions]
    vals = []
    for p in params:
        inner = p.this if isinstance(p, exp.DataTypeParam) else p
        vals.append(inner.name if hasattr(inner, "name") else "")
    try:
        prec = int(vals[0]) if vals else None
        scale = int(vals[1]) if len(vals) > 1 else 0
    except ValueError:
        return None
    if prec is None:
        return exp.DataType.build("DECIMAL")
    if scale == 0:
        if prec <= 9:
            return exp.DataType.build("INT")
        if prec <= 18:
            return exp.DataType.build("BIGINT")
    return exp.DataType.build(f"DECIMAL({prec}, {scale})")


def schema_from_ddl(ddl_sqls: list[str]) -> SchemaInfo:
    info = SchemaInfo()
    for sql in ddl_sqls:
        if not re.match(r"^\s*CREATE\s+TABLE\b", sql, re.I):
            continue
        try:
            tree = sqlglot.parse_one(sql, read="oracle")
        except Exception:
            continue
        tname = tree.find(exp.Table)
        if tname is None:
            continue
        cols: dict[str, str] = {}
        pg_cols: dict[str, str] = {}
        for cd in tree.find_all(exp.ColumnDef):
            dt = cd.args.get("kind")
            if dt is None:
                continue
            name = cd.name.lower()
            pg = _pg_dtype(dt)
            pg_cols[name] = pg.sql(dialect="postgres")
            cols[name] = pg_cols[name].lower()
            if dt.this in (exp.DataType.Type.DATE, exp.DataType.Type.TIMESTAMP, exp.DataType.Type.TIMESTAMPTZ,
                           exp.DataType.Type.TIMESTAMPLTZ, exp.DataType.Type.DATETIME):
                info.date_columns.add(name)
        info.tables[tname.name.lower()] = cols
        info.pg_types[tname.name.lower()] = pg_cols
    return info


def _pg_dtype(dt: exp.DataType) -> exp.DataType:
    if dt.this == exp.DataType.Type.DATE:
        return exp.DataType.build("TIMESTAMP(0)")
    if dt.this == exp.DataType.Type.DECIMAL:
        return _pg_type_for_number(dt) or dt
    return dt


def convert_ddl(sql: str) -> RuleResult:
    res = RuleResult()
    text = sql.strip().rstrip(";").strip()
    if re.match(r"^\s*CREATE\s+SEQUENCE\b", text, re.I):
        s = text
        s = re.sub(r"\bNOCACHE\b", "", s, flags=re.I)
        s = re.sub(r"\bNOORDER\b|\bORDER\b", "", s, flags=re.I)
        s = re.sub(r"\bNOCYCLE\b", "NO CYCLE", s, flags=re.I)
        s = re.sub(r"\bNOMINVALUE\b", "NO MINVALUE", s, flags=re.I)
        s = re.sub(r"\bNOMAXVALUE\b", "NO MAXVALUE", s, flags=re.I)
        s = re.sub(r"\bMAXVALUE\s+(\d{20,})", "NO MAXVALUE", s, flags=re.I)
        res.pg_sql = re.sub(r"\s+", " ", s).strip()
        res.notes.append("sequence options normalised for PostgreSQL (NOCACHE/NOORDER removed)")
        return res
    tokenized, mapping = tokenize_placeholders(text)
    _tls.buf = res.warnings
    try:
        tree = sqlglot.parse_one(tokenized, read="oracle")

        def fn(node: exp.Expression) -> exp.Expression:
            if isinstance(node, exp.DataType):
                if node.this == exp.DataType.Type.DATE:
                    res.notes.append("DATE -> TIMESTAMP(0) (Oracle DATE keeps the time of day)")
                    return exp.DataType.build("TIMESTAMP(0)")
                if node.this == exp.DataType.Type.DECIMAL:
                    new = _pg_type_for_number(node)
                    if new is not None and new.sql(dialect="postgres") != node.sql(dialect="postgres"):
                        res.notes.append(f"NUMBER -> {new.sql(dialect='postgres')}")
                        return new
            return node

        tree = tree.transform(fn)
        tree = _pass_sysdate(tree, res.notes)
        out = tree.sql(dialect="postgres", pretty=True)
    except Exception as exc:
        res.error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
        return res
    finally:
        _tls.buf = None
    res.pg_sql = restore_placeholders(out, mapping)
    res.notes = list(dict.fromkeys(res.notes))
    res.residual = residual_constructs(res.pg_sql, text)
    return res


# ---------------------------------------------------------------------------- JDBC call escape
_CALL = re.compile(r"^\s*\{\s*(\?\s*=\s*)?call\s+([\w.\"]+)\s*(\(.*\))?\s*\}\s*$", re.I | re.S)


def convert_call(sql: str) -> RuleResult:
    res = RuleResult()
    m = _CALL.match(sql.strip())
    if not m:
        res.error = "unrecognised call syntax"
        return res
    target = m.group(2).replace('"', "").lower()
    res.pg_sql = "{" + (m.group(1) or "") + "call " + target + (m.group(3) or "") + "}"
    res.notes.append(f"call target lower-cased (-> {target}); depends on the converted PL/SQL object")
    res.flags.append(f"call:{target}")
    return res


def convert_rules(stmt: Stmt, schema: SchemaInfo) -> RuleResult:
    if stmt.kind == "plsql":
        return RuleResult(error="PL/SQL needs the LLM converter")
    if stmt.kind == "jdbc_call":
        return convert_call(stmt.oracle_sql)
    if stmt.kind == "ddl":
        return convert_ddl(stmt.oracle_sql)
    return convert_query(stmt.oracle_sql, schema)
