"""Discovery: find every SQL statement in a Java code base (JDBC strings, MyBatis XML, JPA native queries,
.sql / PL/SQL scripts) and note application-level Oracle dependencies (driver, dialect, config)."""
from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Callable

from defusedxml import ElementTree as SafeET

from app.core.security import Finding, scan_injection
from app.flows.oracle_pg.constructs import detect, tier_for
from app.flows.oracle_pg.models import Stmt

Emit = Callable[..., None]

# ----------------------------------------------------------------------------- SQL recognition
_SQL_START = [
    re.compile(r"^\s*\{\s*(\?\s*=\s*)?call\b", re.I),
    re.compile(r"^\s*SELECT\b.+\bFROM\b", re.I | re.S),
    re.compile(r"^\s*INSERT\s+(INTO|ALL)\b", re.I),
    re.compile(r"^\s*UPDATE\s+\S+(\s+\w+)?\s+SET\b", re.I | re.S),
    re.compile(r"^\s*DELETE\s+(FROM\s+)?\S+", re.I),
    re.compile(r"^\s*MERGE\s+INTO\b", re.I),
    re.compile(r"^\s*WITH\s+\w+(\s*\([^)]*\))?\s+AS\s*\(", re.I | re.S),
    re.compile(r"^\s*(CREATE|ALTER|DROP|TRUNCATE)\s+(OR\s+REPLACE\s+)?(TABLE|INDEX|SEQUENCE|VIEW|SYNONYM|PROCEDURE|FUNCTION|PACKAGE)\b", re.I),
    re.compile(r"^\s*CALL\s+\w+", re.I),
    re.compile(r"^\s*(BEGIN|DECLARE)\b.*\bEND\s*;?\s*$", re.I | re.S),
]


def looks_like_sql(text: str) -> bool:
    if len(text.strip()) < 12:
        return False
    return any(rx.search(text) for rx in _SQL_START)


def _kind_for_sql(sql: str, default: str) -> str:
    if re.match(r"^\s*\{\s*(\?\s*=\s*)?call\b", sql, re.I) or re.match(r"^\s*CALL\s+\w+", sql, re.I):
        return "jdbc_call"
    if re.match(r"^\s*(BEGIN|DECLARE)\b", sql, re.I) or re.match(
            r"^\s*CREATE\s+(OR\s+REPLACE\s+)?(EDITIONABLE\s+)?(PACKAGE|PROCEDURE|FUNCTION|TRIGGER|TYPE)\b", sql, re.I):
        return "plsql"
    if re.match(r"^\s*(CREATE|ALTER|DROP|TRUNCATE)\b", sql, re.I):
        return "ddl"
    return default


# ----------------------------------------------------------------------------- Java lexer
class _Tok:
    __slots__ = ("t", "v", "s", "e")

    def __init__(self, t: str, v: str, s: int, e: int) -> None:
        self.t, self.v, self.s, self.e = t, v, s, e


_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", '"': '"', "'": "'", "\\": "\\", "0": "\0"}


def _lex_java(src: str) -> tuple[list[_Tok], list[tuple[int, str]]]:
    toks: list[_Tok] = []
    comments: list[tuple[int, str]] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            comments.append((i, src[i:j]))
            i = j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments.append((i, src[i:j]))
            i = j
        elif src.startswith('"""', i):
            j = src.find('"""', i + 3)
            j = n if j < 0 else j
            raw = src[i + 3:j]
            raw = raw[raw.find("\n") + 1:] if "\n" in raw else raw
            toks.append(_Tok("str", textwrap.dedent(raw).strip(), i, min(n, j + 3)))
            i = min(n, j + 3)
        elif c == '"':
            j, buf = i + 1, []
            while j < n and src[j] != '"':
                if src[j] == "\\" and j + 1 < n:
                    buf.append(_ESC.get(src[j + 1], "\\" + src[j + 1]))
                    j += 2
                else:
                    if src[j] == "\n":
                        break
                    buf.append(src[j])
                    j += 1
            toks.append(_Tok("str", "".join(buf), i, j + 1))
            i = j + 1
        elif c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            toks.append(_Tok("chr", src[i:j + 1], i, j + 1))
            i = j + 1
        elif c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(_Tok("id", src[i:j], i, j))
            i = j
        elif c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            toks.append(_Tok("num", src[i:j], i, j))
            i = j
        else:
            toks.append(_Tok("p", c, i, i + 1))
            i += 1
    return toks, comments


def _skip_parens(toks: list[_Tok], k: int) -> int:
    """toks[k] is '(' - return index after the matching ')'."""
    depth = 0
    while k < len(toks):
        if toks[k].t == "p" and toks[k].v == "(":
            depth += 1
        elif toks[k].t == "p" and toks[k].v == ")":
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return k


def _string_groups(toks: list[_Tok]) -> list[dict]:
    """Group string literals joined with '+' (optionally with identifiers in between = dynamic SQL)."""
    groups: list[dict] = []
    i = 0
    while i < len(toks):
        if toks[i].t != "str":
            i += 1
            continue
        parts = [toks[i].v]
        start, end = toks[i].s, toks[i].e
        dynamic = False
        dyn_names: list[str] = []
        k = i + 1
        while k < len(toks) and toks[k].t == "p" and toks[k].v == "+":
            nxt = k + 1
            if nxt < len(toks) and toks[nxt].t == "str":
                parts.append(toks[nxt].v)
                end = toks[nxt].e
                k = nxt + 1
                continue
            # identifier chain (a.b.c or a.b()) followed by '+ "string"' => dynamic fragment
            m = nxt
            if m < len(toks) and toks[m].t == "id":
                name = toks[m].v
                m += 1
                while m < len(toks) and toks[m].t == "p" and toks[m].v == "." and m + 1 < len(toks) and toks[m + 1].t == "id":
                    name = toks[m + 1].v
                    m += 2
                if m < len(toks) and toks[m].t == "p" and toks[m].v == "(":
                    m = _skip_parens(toks, m)
                if m + 1 < len(toks) and toks[m].t == "p" and toks[m].v == "+" and toks[m + 1].t == "str":
                    dynamic = True
                    dyn_names.append(name)
                    parts.append(f" __DYN_{name}__ ")
                    parts.append(toks[m + 1].v)
                    end = toks[m + 1].e
                    k = m + 2
                    continue
            break
        groups.append({"value": "".join(parts), "start": start, "end": end, "dynamic": dynamic, "dyn": dyn_names})
        i = k
    return groups


_METHOD_RX = re.compile(
    r"(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\],.? ]+?\s+(\w+)\s*\([^;{}()]*(?:\([^)]*\)[^;{}()]*)*\)\s*(?:throws\s+[\w., ]+)?\s*\{")


def _enclosing_method(src: str, pos: int) -> str | None:
    last = None
    for m in _METHOD_RX.finditer(src, 0, pos):
        if m.group(1) not in ("if", "for", "while", "switch", "catch", "try", "synchronized"):
            last = m.group(1)
    return last


def _line_of(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def _jpa_context(src: str, start: int, end: int) -> tuple[str | None, str | None]:
    """Return (annotation_kind, forward_method_name) for literals inside @Query(...)."""
    back = src[max(0, start - 400):start]
    idx = back.rfind("@Query")
    if idx < 0 or ";" in back[idx:] or "}" in back[idx:]:
        return None, None
    semi = src.find(";", end)
    seg = src[start:semi if semi > 0 else end + 400]
    native = bool(re.search(r"nativeQuery\s*=\s*true", seg))
    after = src[end:semi if semi > 0 else end + 400]  # text after the literal: rest of annotation + method signature
    mm = re.search(r"\)\s*(?:@\w+(?:\([^)]*\))?\s*)*[\w<>\[\],.? ]+?\s+(\w+)\s*\(", after)
    return ("native" if native else "jpql"), (mm.group(1) if mm else None)


# ----------------------------------------------------------------------------- per-file extractors
def _from_java(path: Path, rel: str, src: str, counter: Callable[[], str]) -> list[Stmt]:
    toks, _comments = _lex_java(src)
    cls = path.stem
    out: list[Stmt] = []
    for g in _string_groups(toks):
        sql = g["value"].strip()
        if not looks_like_sql(sql):
            continue
        before = src[max(0, g["start"] - 160):g["start"]]
        jpa_kind, jpa_method = _jpa_context(src, g["start"], g["end"])
        kind = _kind_for_sql(sql, "jdbc")
        if re.search(r"createQuery\s*\(\s*$", before) or jpa_kind == "jpql":
            kind = "jpql"
        elif jpa_kind == "native" or re.search(r"createNativeQuery\s*\(\s*$", before):
            kind = "jpa_native" if kind == "jdbc" else kind
        m = re.search(r"(\w+)\s*=\s*$", before)
        const = m.group(1) if m else None
        method = jpa_method or _enclosing_method(src, g["start"])
        name = const if (const and const.isupper()) else (method or const or "inline")
        stmt = Stmt(id=counter(), kind=kind, file=rel, line=_line_of(src, g["start"]), label=f"{cls}.{name}",
                    oracle_sql=sql, dynamic=g["dynamic"])
        if g["dynamic"]:
            stmt.meta["dynamic_vars"] = g["dyn"]
        out.append(stmt)
    return out


def _flatten(el, fragments: dict, dyn_flag: list[bool]) -> str:
    parts = [el.text or ""]
    for child in el:
        tag = child.tag
        if tag == "selectKey":
            parts.append(child.tail or "")
            continue
        if tag == "include":
            ref = child.attrib.get("refid", "")
            frag = fragments.get(ref)
            parts.append(_flatten(frag, fragments, dyn_flag) if frag is not None else f" /* include {ref} */ ")
        elif tag in ("if", "choose", "when", "otherwise", "foreach", "where", "set", "trim", "bind"):
            dyn_flag[0] = True
            if tag == "where":
                parts.append(" WHERE ")
            elif tag == "set":
                parts.append(" SET ")
            if tag != "bind":
                parts.append(_flatten(child, fragments, dyn_flag))
        else:
            parts.append(_flatten(child, fragments, dyn_flag))
        parts.append(child.tail or "")
    return "".join(parts)


def _strip_line_comments(sql: str) -> str:
    out = []
    for line in sql.splitlines():
        in_str = False
        cut = len(line)
        for i, ch in enumerate(line):
            if ch == "'":
                in_str = not in_str
            elif not in_str and line.startswith("--", i):
                cut = i
                break
        out.append(line[:cut])
    return "\n".join(out)


def _norm_ws(sql: str) -> str:
    return re.sub(r"\s+", " ", _strip_line_comments(sql)).strip()


def _from_mybatis(rel: str, src: str, counter: Callable[[], str]) -> list[Stmt]:
    try:
        root = SafeET.fromstring(src.encode("utf-8"))
    except Exception:
        return []
    if root.tag != "mapper":
        return []
    ns = root.attrib.get("namespace", Path(rel).stem)
    short = ns.rsplit(".", 1)[-1]
    fragments = {e.attrib.get("id", ""): e for e in root.iter("sql")}
    out: list[Stmt] = []
    for el in root:
        if el.tag not in ("select", "insert", "update", "delete"):
            continue
        sid = el.attrib.get("id", "?")
        idx = src.find(f'id="{sid}"')
        line = _line_of(src, idx) if idx >= 0 else 1
        for sk in el.findall("selectKey"):
            sk_sql = _norm_ws("".join(sk.itertext()))
            if looks_like_sql(sk_sql):
                out.append(Stmt(id=counter(), kind="mybatis", file=rel, line=line, label=f"{short}.{sid}#selectKey",
                                oracle_sql=sk_sql))
        dyn = [False]
        sql = _norm_ws(_flatten(el, fragments, dyn))
        if not looks_like_sql(sql):
            continue
        st = Stmt(id=counter(), kind=_kind_for_sql(sql, "mybatis") if _kind_for_sql(sql, "mybatis") == "jdbc_call" else "mybatis",
                  file=rel, line=line, label=f"{short}.{sid}", oracle_sql=sql, dynamic=False)
        if dyn[0]:
            st.meta["mybatis_dynamic"] = True
        if el.attrib.get("resultType", "").lower() in ("map", "hashmap", "java.util.map", "java.util.hashmap"):
            st.meta["result_map"] = True
        if "${" in sql:
            st.dynamic = True
            st.meta["raw_substitution"] = True
        out.append(st)
    return out


_PLSQL_START = re.compile(
    r"^\s*(CREATE\s+(OR\s+REPLACE\s+)?(EDITIONABLE\s+|NONEDITIONABLE\s+)?(PACKAGE|PROCEDURE|FUNCTION|TRIGGER|TYPE)\b|DECLARE\b|BEGIN\b)",
    re.I)


def _split_script(text: str) -> list[tuple[int, str]]:
    stmts: list[tuple[int, str]] = []
    buf: list[str] = []
    start, mode = 1, None
    for idx, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if not buf and (not s or s.startswith("--")):
            continue
        if not buf:
            start = idx
            mode = "plsql" if _PLSQL_START.match(s) else "sql"
        if mode == "plsql":
            if s == "/":
                stmts.append((start, "\n".join(buf)))
                buf, mode = [], None
                continue
            buf.append(line)
        else:
            buf.append(line)
            joined = "\n".join(buf)
            if _strip_line_comments(line).rstrip().endswith(";") and joined.count("'") % 2 == 0:
                stmts.append((start, joined.rstrip().rstrip(";")))
                buf, mode = [], None
    if buf:
        stmts.append((start, "\n".join(buf).rstrip().rstrip(";")))
    return stmts


def _from_sql_file(rel: str, src: str, counter: Callable[[], str]) -> list[Stmt]:
    out: list[Stmt] = []
    pkg_index: dict[str, Stmt] = {}
    for line, text in _split_script(src):
        clean = _strip_line_comments(text).strip()
        if not clean:
            continue
        kind = _kind_for_sql(clean, "sql")
        label = Path(rel).stem
        m = re.match(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:EDITIONABLE\s+)?(PACKAGE\s+BODY|PACKAGE|PROCEDURE|FUNCTION|TRIGGER|TYPE|TABLE|SEQUENCE|INDEX|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)", clean, re.I)
        if m:
            label = f"{m.group(1).upper().replace('  ', ' ')} {m.group(2)}"
        if m and m.group(1).upper().startswith("PACKAGE"):
            pkg = m.group(2).upper()
            if pkg in pkg_index:  # merge spec + body into one unit so the converter sees both
                pkg_index[pkg].oracle_sql += "\n/\n" + clean
                pkg_index[pkg].label = f"PACKAGE {m.group(2)} (spec + body)"
                continue
            st = Stmt(id=counter(), kind="plsql", file=rel, line=line, label=label, oracle_sql=clean)
            pkg_index[pkg] = st
            out.append(st)
            continue
        out.append(Stmt(id=counter(), kind=kind, file=rel, line=line, label=label, oracle_sql=clean))
    return out


# ----------------------------------------------------------------------------- app-level (non-SQL) findings
_APP_CHECKS = [
    (r"ojdbc\d*|com\.oracle\.database\.jdbc|oracle\.jdbc", "Oracle JDBC driver dependency",
     "Replace with org.postgresql:postgresql and update the driver class name.", "medium"),
    (r"jdbc:oracle:[a-z]+:", "Oracle JDBC URL", "Switch to jdbc:postgresql://host:5432/db and review connection properties.", "medium"),
    (r"OracleDialect|Oracle\d+[ci]?Dialect|Oracle12cDialect", "Hibernate Oracle dialect",
     "Use org.hibernate.dialect.PostgreSQLDialect (or let Hibernate 6 auto-detect).", "medium"),
    (r"oracle\.jdbc\.OracleTypes|OracleTypes\.CURSOR|oracle\.sql\.", "Oracle-specific JDBC types (REF CURSOR etc.)",
     "REF CURSOR OUT parameters need rework for PostgreSQL (refcursor / SETOF / RETURNS TABLE).", "high"),
    (r"GenerationType\.SEQUENCE|@SequenceGenerator", "JPA sequence generators",
     "Check allocationSize and sequence naming; PostgreSQL sequences differ in caching/gaps.", "low"),
    (r"columnDefinition\s*=\s*\"(NUMBER|VARCHAR2|DATE)", "Oracle column definitions in annotations",
     "Replace with PostgreSQL types (numeric, varchar, timestamp).", "medium"),
    (r"ORA-\d{5}|SQLException.*getErrorCode\(\)", "Oracle error-code handling",
     "Map ORA- codes to PostgreSQL SQLSTATE values (e.g. 23505 for unique violation).", "high"),
]


def scan_app_config(root: Path, files: list[Path]) -> list[Finding]:
    out: list[Finding] = []
    for p in files:
        if p.suffix.lower() not in (".java", ".xml", ".properties", ".yml", ".yaml", ".gradle", ".kt"):
            continue
        try:
            text = p.read_text("utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(root))
        for rx, title, advice, sev in _APP_CHECKS:
            m = re.search(rx, text)
            if m:
                out.append(Finding(sev, f"App change needed: {title}", rel, _line_of(text, m.start()), advice))
        if re.search(r"(?i)password\s*[=:]\s*\S{3,}", text) and p.suffix.lower() in (".properties", ".yml", ".yaml"):
            m = re.search(r"(?i)password\s*[=:]\s*\S{3,}", text)
            out.append(Finding("high", "Hard-coded credential in configuration", rel, _line_of(text, m.start()),
                               "Move secrets to environment variables / a vault before the migration."))
    return out


def _app_security_findings(stmts: list[Stmt]) -> list[Finding]:
    out: list[Finding] = []
    for s in stmts:
        if s.dynamic and s.kind in ("jdbc", "jdbc_call", "jpa_native"):
            out.append(Finding("high", "SQL built by string concatenation", s.file, s.line,
                               f"{s.label}: concatenated variables ({', '.join(s.meta.get('dynamic_vars', []))}) in SQL. "
                               "Use bind parameters to avoid SQL injection; the converter cannot validate dynamic SQL."))
        if s.meta.get("raw_substitution"):
            out.append(Finding("high", "MyBatis ${} raw substitution", s.file, s.line,
                               f"{s.label}: ${{...}} is pasted into the SQL as text (SQL injection risk). Prefer #{{...}}."))
    return out


# ----------------------------------------------------------------------------- entry point
def discover(root: Path, emit: Emit, max_statements: int) -> tuple[list[Stmt], list[Finding], dict]:
    files = sorted(p for p in root.rglob("*") if p.is_file())
    seq = [0]

    def counter() -> str:
        seq[0] += 1
        return f"S{seq[0]:03d}"

    stmts: list[Stmt] = []
    findings: list[Finding] = []
    stats = {"files": len(files), "java": 0, "xml": 0, "sql": 0}
    for p in files:
        rel = str(p.relative_to(root))
        ext = p.suffix.lower()
        try:
            src = p.read_text("utf-8", errors="replace")
        except OSError:
            continue
        found: list[Stmt] = []
        if ext in (".java", ".kt"):
            stats["java"] += 1
            found = _from_java(p, rel, src, counter)
            findings += scan_injection(src, rel)
        elif ext == ".xml":
            stats["xml"] += 1
            found = _from_mybatis(rel, src, counter)
            findings += scan_injection(src, rel)
        elif ext in (".sql", ".pks", ".pkb", ".prc", ".fnc", ".trg", ".ddl"):
            stats["sql"] += 1
            found = _from_sql_file(rel, src, counter)
            findings += scan_injection(src, rel)
        else:
            findings += scan_injection(src, rel)
        if found:
            emit("Discovery", f"{rel}: {len(found)} SQL statement(s)", "info")
        stmts += found

    for s in stmts:
        s.constructs, s.weight = detect(s.oracle_sql, s.kind)
        s.tier = tier_for(s.kind, s.weight)
        if s.kind == "jpql" and not s.constructs:
            s.tier = "trivial"

    if len(stmts) > max_statements:
        emit("Discovery", f"Found {len(stmts)} statements; capping at {max_statements} for this run", "warn")
        stmts = stmts[:max_statements]
    findings += scan_app_config(root, files)
    findings += _app_security_findings(stmts)
    return stmts, findings, stats
