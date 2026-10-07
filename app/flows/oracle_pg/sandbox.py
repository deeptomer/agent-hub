"""PostgreSQL sandbox used by the Validator agent.

Safety model:
  * every run gets its own schema (run_<id>), dropped at the end of the run
  * converted queries are only EXPLAINed (planned, never executed) inside a transaction that is always rolled back
  * PL/pgSQL objects are created inside a transaction that is always rolled back
  * only allow-listed DDL is executed, statement timeouts apply, and model output passes a deny-list first
If DATABASE_URL is not set the validator falls back to a syntax-only check with sqlglot.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

import sqlglot

from app.core.security import output_guard
from app.flows.oracle_pg.rules import SchemaInfo, tokenize_placeholders

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None  # type: ignore

SHIMS_SQL = (Path(__file__).parent / "compat_shims.sql").read_text("utf-8")

_DDL_ALLOWED = re.compile(r"^\s*CREATE\s+(OR\s+REPLACE\s+)?(UNIQUE\s+)?(TABLE|SEQUENCE|INDEX|VIEW)\b", re.I)
_PLPGSQL_ALLOWED = re.compile(
    r"^\s*(CREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE|TRIGGER|TYPE|VIEW)\b|CREATE\s+SCHEMA\b|CREATE\s+(OR\s+REPLACE\s+)?SEQUENCE\b)",
    re.I)


def split_pg_statements(sql: str) -> list[str]:
    """Split a script on ';' while respecting '...' strings, "..." identifiers, $tag$...$tag$ bodies and comments."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        c = sql[i]
        if c == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'" and j + 1 < n and sql[j + 1] == "'":
                    j += 2
                    continue
                if sql[j] == "'":
                    break
                j += 1
            buf.append(sql[i:j + 1])
            i = j + 1
        elif c == '"':
            j = sql.find('"', i + 1)
            j = n - 1 if j < 0 else j
            buf.append(sql[i:j + 1])
            i = j + 1
        elif c == "$":
            m = re.match(r"\$([A-Za-z_]\w*)?\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j < 0 else j + len(tag)
                buf.append(sql[i:j])
                i = j
            else:
                buf.append(c)
                i += 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            buf.append(sql[i:j])
            i = j
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2)
            j = n if j < 0 else j + 2
            buf.append(sql[i:j])
            i = j
        elif c == ";":
            s = "".join(buf).strip()
            if s:
                out.append(s)
            buf = []
            i += 1
        else:
            buf.append(c)
            i += 1
    s = "".join(buf).strip()
    if s:
        out.append(s)
    return out


def _first_line(exc: Exception) -> str:
    msg = str(exc).strip().splitlines()
    return (msg[0] if msg else type(exc).__name__)[:300]


_PH_TOKEN = re.compile(r"__ph(\d+)__", re.I)
_TYPING_ERR = re.compile(r"unknown|could not determine data type", re.I)
_PARAM_VARIANTS = ["NULL", "CAST(NULL AS numeric)", "CAST(NULL AS text)", "CAST(NULL AS timestamp)"]


def tokenize_for_validation(sql: str) -> tuple[str, bool]:
    """Turn bind placeholders into __phN__ tokens. Second value: raw ${} substitution found (cannot be planned)."""
    tokenized, mapping = tokenize_placeholders(sql)
    return tokenized, any(v.startswith("${") for v in mapping.values())


class Sandbox:
    def __init__(self, dsn: str | None, run_id: str) -> None:
        self.dsn = dsn
        self.schema = f"run_{run_id[:8]}"
        self.live = False
        self.mode = "syntax-only"
        self.version: str | None = None
        self.error: str | None = None
        self._local = threading.local()
        self._conns: list = []
        self._lock = threading.Lock()
        self.known_calls: set[str] = set()

    # ------------------------------------------------------------------ lifecycle
    def setup(self) -> None:
        if not self.dsn or psycopg is None:
            self.error = "DATABASE_URL not set" if not self.dsn else "psycopg not installed"
            return
        try:
            with psycopg.connect(self.dsn, autocommit=True, connect_timeout=8) as conn:
                self.version = conn.execute("SHOW server_version").fetchone()[0]
                conn.execute(f'CREATE SCHEMA "{self.schema}"')
                conn.execute(f'SET search_path TO "{self.schema}", pg_catalog')
                for stmt in split_pg_statements(SHIMS_SQL):
                    conn.execute(stmt)
            self.live = True
            self.mode = "postgres"
        except Exception as exc:
            self.error = _first_line(exc)
            self.live = False

    def teardown(self) -> None:
        with self._lock:
            conns, self._conns = self._conns, []
        for c in conns:
            try:
                c.close()
            except Exception:
                pass
        if self.live and psycopg is not None:
            try:
                with psycopg.connect(self.dsn, autocommit=True, connect_timeout=8) as conn:
                    conn.execute(f'DROP SCHEMA IF EXISTS "{self.schema}" CASCADE')
            except Exception:
                pass

    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is None or c.closed:
            c = psycopg.connect(self.dsn, autocommit=False, connect_timeout=8)
            self._local.conn = c
            with self._lock:
                self._conns.append(c)
        return c

    def _prep(self, cur) -> None:
        cur.execute(f'SET LOCAL search_path TO "{self.schema}", pg_catalog')
        cur.execute("SET LOCAL statement_timeout = '8s'")
        cur.execute("SET LOCAL lock_timeout = '2s'")

    # ------------------------------------------------------------------ DDL (persists for the life of the run)
    def apply_ddl(self, sql: str) -> tuple[bool, str | None]:
        reason = output_guard(sql)
        if reason:
            return False, reason
        if not self.live:
            return self._syntax_only(sql)
        stmts = split_pg_statements(sql)
        for s in stmts:
            if not _DDL_ALLOWED.match(s):
                return False, "blocked: only CREATE TABLE/SEQUENCE/INDEX/VIEW is executed in the sandbox"
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                self._prep(cur)
                for s in stmts:
                    cur.execute(s)
            conn.commit()
            return True, None
        except Exception as exc:
            conn.rollback()
            return False, _first_line(exc)

    # ------------------------------------------------------------------ queries (EXPLAIN only)
    def validate_query(self, sql: str) -> tuple[str, str | None]:
        """Return (status, error); status is ok | inconclusive | failed | skipped.
        inconclusive = syntax accepted but PostgreSQL could not infer a bind-parameter type (needs a cast or real values)."""
        reason = output_guard(sql)
        if reason:
            return "failed", reason
        if sql.strip().startswith("{"):
            return self._validate_call(sql)
        if not split_pg_statements(sql):
            return "failed", "empty statement"
        tokenized, raw = tokenize_for_validation(sql)
        if raw:
            ok, err = self._syntax_only(_PH_TOKEN.sub("NULL", tokenized))
            return ("skipped", "contains ${} raw substitution - cannot be planned") if ok else ("failed", err)
        if not self.live:
            ok, err = self._syntax_only(_PH_TOKEN.sub("NULL", tokenized))
            return ("ok" if ok else "failed"), err
        conn = self._conn()
        first_err: str | None = None
        for variant in _PARAM_VARIANTS:
            sub = _PH_TOKEN.sub(variant, tokenized)
            try:
                with conn.cursor() as cur:
                    self._prep(cur)
                    for s in split_pg_statements(sub):
                        cur.execute("EXPLAIN " + s)
                return "ok", None
            except Exception as exc:
                msg = _first_line(exc)
                first_err = first_err or msg
                if not _TYPING_ERR.search(msg):
                    return "failed", msg
            finally:
                try:
                    conn.rollback()
                except Exception:
                    pass
            if "__ph" not in tokenized.lower():
                break
        return "inconclusive", first_err

    def _validate_call(self, sql: str) -> tuple[str, str | None]:
        m = re.search(r"call\s+([\w.\"]+)", sql, re.I)
        if not m:
            return "failed", "unrecognised call syntax"
        target = m.group(1).lower().replace('"', "")
        if target in self.known_calls:
            return "ok", None
        return "failed", f"call target {target} was not created by a converted PL/SQL unit in this run"

    # ------------------------------------------------------------------ PL/pgSQL (created, then rolled back)
    def validate_plpgsql(self, sql: str) -> tuple[str, str | None, list[str]]:
        reason = output_guard(sql)
        if reason:
            return "failed", reason, []
        stmts = split_pg_statements(sql)
        if not stmts:
            return "failed", "empty output", []
        for s in stmts:
            if not _PLPGSQL_ALLOWED.match(s):
                return "failed", "blocked: only CREATE FUNCTION/PROCEDURE/SCHEMA/TYPE/TRIGGER is executed in the sandbox", []
        created = []
        for s in stmts:
            m = re.match(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+([\w.\"]+)", s, re.I)
            if m:
                created.append(m.group(1).lower().replace('"', ""))
        if not self.live:
            for s in stmts:
                m = re.match(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b", s, re.I)
                if m and not re.search(r"\$\w*\$", s) and "AS" not in s.upper():
                    return "failed", "function body is not dollar-quoted", created
            return "skipped", "no live PostgreSQL: structural check only", created
        conn = self._conn()
        try:
            with conn.cursor() as cur:
                self._prep(cur)
                cur.execute("SET LOCAL check_function_bodies = on")
                for s in stmts:
                    cur.execute(s)
            return "ok", None, created
        except Exception as exc:
            return "failed", _first_line(exc), created
        finally:
            try:
                conn.rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------ helpers
    def _syntax_only(self, sql: str) -> tuple[bool, str | None]:
        try:
            for s in split_pg_statements(sql):
                sqlglot.parse_one(s, read="postgres")
            return True, None
        except Exception as exc:
            return False, f"syntax: {_first_line(exc)}"

    def introspect(self) -> SchemaInfo:
        info = SchemaInfo()
        if not self.live:
            return info
        try:
            conn = self._conn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT table_name, column_name, data_type FROM information_schema.columns "
                    "WHERE table_schema = %s ORDER BY table_name, ordinal_position", (self.schema,))
                for t, c, ty in cur.fetchall():
                    info.tables.setdefault(t, {})[c] = ty
            conn.rollback()
        except Exception:
            pass
        return info


def cleanup_stale_schemas(dsn: str | None) -> int:
    """Drop leftovers from crashed runs (called once at start-up)."""
    if not dsn or psycopg is None:
        return 0
    n = 0
    try:
        with psycopg.connect(dsn, autocommit=True, connect_timeout=8) as conn:
            rows = conn.execute("SELECT nspname FROM pg_namespace WHERE nspname ~ '^run_[0-9a-f]{8}$'").fetchall()
            for (name,) in rows:
                conn.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
                n += 1
    except Exception:
        pass
    return n
