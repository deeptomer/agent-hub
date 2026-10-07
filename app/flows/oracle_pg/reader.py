"""Code Reader agent: profiles a new Java project and finds SQL the rule-based extractor could not assemble.

Two halves, like every agent here:
  1. deterministic - project profile (frameworks, build tool, SQL per file) and *gap detection*: SQL-looking string
     literals that are not part of any extracted statement (StringBuilder chains, String.format, helper methods, ...).
  2. Claude (optional) - reads only the files with gaps and reconstructs the complete statements. Nothing it returns is
     trusted blindly: each statement must look like SQL, and its table/column words must actually occur in the file."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Callable

from app.config import settings
from app.core.llm import LLM
from app.core.security import Finding
from app.flows.oracle_pg import extract
from app.flows.oracle_pg.constructs import detect, tier_for
from app.flows.oracle_pg.llm_agents import read_with_llm
from app.flows.oracle_pg.models import Stmt

Emit = Callable[..., None]

MAX_GAP_FILES = 8          # Claude reads at most this many files per run
MAX_READER_STATEMENTS = 40  # and adds at most this many statements
MAX_FILE_CHARS = 14_000

_FRAMEWORKS = [
    ("Plain JDBC", re.compile(r"java\.sql\.|PreparedStatement|CallableStatement|DriverManager")),
    ("Spring JdbcTemplate", re.compile(r"JdbcTemplate|NamedParameterJdbcTemplate|SimpleJdbc")),
    ("MyBatis", re.compile(r"org\.apache\.ibatis|mybatis|<mapper\b")),
    ("JPA / Hibernate", re.compile(r"javax\.persistence|jakarta\.persistence|org\.hibernate|EntityManager")),
    ("Spring Data", re.compile(r"JpaRepository|CrudRepository|PagingAndSortingRepository|@Query\b")),
    ("jOOQ", re.compile(r"org\.jooq")),
    ("QueryDSL", re.compile(r"com\.querydsl")),
    ("Oracle JDBC driver", re.compile(r"oracle\.jdbc|ojdbc|jdbc:oracle")),
]

_STRONG = ("select", "from", "where", "join", "insert into", "values", "update", "set", "delete", "order by",
           "group by", "having", "union", "merge into", "connect by", "start with")
_START = re.compile(
    r"^\s*(?:(?:select|from|where|join|left\s+join|inner\s+join|insert\s+into|values|update|set|delete|order\s+by|group\s+by|"
    r"having|union|merge\s+into|connect\s+by|start\s+with)\b|and\s+[\w.]+\s*(?:[=<>!]|in\b|like\b|is\b|between\b)|"
    r"on\s+\w+\.\w+\s*=)", re.I)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _is_fragment(text: str) -> bool:
    t = text.strip()
    if len(t) < 6:
        return False
    if _START.match(t):
        return True
    low = " " + _norm(t) + " "
    return sum(1 for k in _STRONG if f" {k} " in low) >= 2


def project_profile(root: Path, files: list[Path], stmts: list[Stmt]) -> dict:
    """What kind of Java project is this? Cheap, deterministic, shown in the report."""
    hits: Counter[str] = Counter()
    build = "unknown"
    classes_with_sql = Counter(s.file for s in stmts)
    for p in files:
        name = p.name.lower()
        if name == "pom.xml":
            build = "Maven"
        elif name in ("build.gradle", "build.gradle.kts") and build == "unknown":
            build = "Gradle"
        if p.suffix.lower() not in (".java", ".kt", ".xml", ".properties", ".yml", ".yaml", ".gradle"):
            continue
        try:
            text = p.read_text("utf-8", errors="ignore")[:200_000]
        except OSError:
            continue
        for fw, rx in _FRAMEWORKS:
            if rx.search(text):
                hits[fw] += 1
    return {
        "build_tool": build,
        "frameworks": [{"name": k, "files": v} for k, v in hits.most_common()],
        "sql_by_file": [{"file": f, "statements": n} for f, n in classes_with_sql.most_common(8)],
    }


def find_gaps(root: Path, files: list[Path], stmts: list[Stmt]) -> dict[str, list[tuple[int, str]]]:
    """SQL-looking string literals in Java files that are not inside any extracted statement."""
    covered: dict[str, str] = {}
    for s in stmts:
        covered[s.file] = covered.get(s.file, "") + " " + _norm(s.oracle_sql)
    gaps: dict[str, list[tuple[int, str]]] = {}
    for p in files:
        if p.suffix.lower() not in (".java", ".kt"):
            continue
        rel = str(p.relative_to(root))
        try:
            src = p.read_text("utf-8", errors="replace")
        except OSError:
            continue
        toks, _ = extract._lex_java(src)
        have = covered.get(rel, "")
        found: list[tuple[int, str]] = []
        for t in toks:
            if t.t != "str" or not _is_fragment(t.v):
                continue
            if _norm(t.v) and _norm(t.v) in have:
                continue
            found.append((extract._line_of(src, t.s), t.v.strip()[:140]))
        if found:
            gaps[rel] = found
    return gaps


def _valid_reconstruction(sql: str, src_lower: str) -> str | None:
    """Return a reason if the model's SQL should be rejected, else None."""
    if len(sql) > 8000:
        return "too long"
    if not extract.looks_like_sql(sql):
        return "does not look like SQL"
    words = set(re.findall(r"[a-z_][a-z0-9_]{3,}", sql.lower()))
    words -= {"select", "from", "where", "insert", "into", "values", "update", "delete", "order", "group", "having", "union",
              "join", "left", "right", "inner", "outer", "null", "like", "count", "distinct", "when", "then", "else", "case",
              "with", "merge", "using", "match", "matched", "desc", "asc", "between", "exists", "rownum", "sysdate", "dual"}
    if not words:
        return None
    present = sum(1 for w in words if w in src_lower)
    if present / len(words) < 0.8:
        return "uses names that do not occur in the file"
    return None


def run_reader(root: Path, stmts: list[Stmt], findings: list[Finding], stats: dict, llm: LLM, emit: Emit) -> list[Stmt]:
    """Adds `stats['profile']`, may append reconstructed statements, and records unresolved gaps as findings."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    stats["profile"] = project_profile(root, files, stmts)
    prof = stats["profile"]
    fw = ", ".join(f"{f['name']} ({f['files']})" for f in prof["frameworks"][:5]) or "none detected"
    emit("Code Reader", f"Project profile: build {prof['build_tool']}; data access via {fw}", "info")

    gaps = find_gaps(root, files, stmts)
    n_frag = sum(len(v) for v in gaps.values())
    stats["reader"] = {"gap_files": len(gaps), "gap_fragments": n_frag, "reconstructed": 0, "rejected": 0, "used_llm": False}
    if not gaps:
        emit("Code Reader", "Every SQL string in the Java code is part of an extracted statement", "ok")
        return stmts

    emit("Code Reader", f"{n_frag} SQL-looking string(s) in {len(gaps)} Java file(s) are not part of any extracted statement "
                        "(StringBuilder chains, String.format, helper methods)", "warn" if not llm.available else "info")
    unresolved = dict(gaps)
    if llm.available:
        stats["reader"]["used_llm"] = True
        ranked = sorted(gaps.items(), key=lambda kv: -len(kv[1]))[:MAX_GAP_FILES]
        existing = {_norm(s.oracle_sql) for s in stmts}
        seq = [len(stmts)]
        added: list[Stmt] = []
        for rel, frags in ranked:
            if len(added) >= MAX_READER_STATEMENTS:
                break
            src = (root / rel).read_text("utf-8", errors="replace")
            emit("Code Reader", f"Claude is reading {rel} ({len(frags)} unassembled fragment(s))", "info")
            res = read_with_llm(llm, rel, src[:MAX_FILE_CHARS], frags)
            got = 0
            for item in (res or {}).get("statements", [])[:12]:
                sql = str(item.get("oracle_sql", "")).strip().rstrip(";") if str(item.get("kind", "")) != "plsql" else str(item.get("oracle_sql", "")).strip()
                reason = _valid_reconstruction(sql, src.lower())
                if reason:
                    stats["reader"]["rejected"] += 1
                    emit("Code Reader", f"Rejected a reconstruction in {rel}: {reason}", "warn")
                    continue
                if _norm(sql) in existing:
                    continue
                existing.add(_norm(sql))
                seq[0] += 1
                kind = extract._kind_for_sql(sql, "jdbc")
                line = int(item.get("line") or frags[0][0])
                method = re.sub(r"[^\w]", "", str(item.get("method") or "inline"))[:40] or "inline"
                st = Stmt(id=f"S{seq[0]:03d}", kind=kind, file=rel, line=line, label=f"{Path(rel).stem}.{method}", oracle_sql=sql,
                          dynamic=bool(item.get("dynamic")))
                st.meta["reader"] = "llm"
                st.meta["reader_note"] = str(item.get("note", ""))[:300]
                if item.get("dynamic_parts"):
                    st.meta["dynamic_vars"] = [str(x)[:40] for x in item["dynamic_parts"]][:6]
                st.constructs, st.weight = detect(st.oracle_sql, st.kind)
                st.tier = tier_for(st.kind, st.weight)
                added.append(st)
                got += 1
            if got:
                unresolved.pop(rel, None)
                emit("Code Reader", f"{rel}: reconstructed {got} statement(s)", "ok")
        stmts = stmts + added[:MAX_READER_STATEMENTS]
        stats["reader"]["reconstructed"] = len(added)
        if len(gaps) > len(ranked):
            emit("Code Reader", f"Read the {len(ranked)} files with the most gaps; {len(gaps) - len(ranked)} more were not read (cost cap)", "warn")
    else:
        emit("Code Reader", "Claude is not available for this run, so these fragments are listed as findings instead", "warn")

    for rel, frags in unresolved.items():
        line, text = frags[0]
        findings.append(Finding("medium", "SQL not extracted by the Code Reader", rel, line,
                                f"{len(frags)} SQL-looking fragment(s), first: \"{text[:90]}\". The statement is probably assembled "
                                "at runtime; review by hand or run with Claude enabled so the Code Reader can reconstruct it."))
    return stmts
