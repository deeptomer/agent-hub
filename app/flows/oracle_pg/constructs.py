"""Detect Oracle-specific constructs in SQL / PL/SQL text and score migration complexity."""
from __future__ import annotations

import re

# (label, regex, weight). Weights roughly track how hard the construct is to migrate.
_RULES: list[tuple[str, str, int]] = [
    ("ROWNUM", r"\bROWNUM\b", 3),
    ("CONNECT BY (hierarchical query)", r"\bCONNECT\s+BY\b|\bSTART\s+WITH\b(?![^;]*\bINCREMENT\b)", 5),
    ("SYS_CONNECT_BY_PATH / LEVEL / SIBLINGS", r"\bSYS_CONNECT_BY_PATH\b|\bORDER\s+SIBLINGS\b|\bCONNECT_BY_ROOT\b", 2),
    ("DECODE", r"\bDECODE\s*\(", 1),
    ("NVL / NVL2", r"\bNVL2?\s*\(", 1),
    ("(+) outer join", r"\(\s*\+\s*\)", 2),
    ("MERGE", r"^\s*MERGE\s+INTO\b", 3),
    ("Sequence NEXTVAL/CURRVAL", r"\b\w+\.(NEXTVAL|CURRVAL)\b", 1),
    ("SYSDATE / SYSTIMESTAMP", r"\bSYS(DATE|TIMESTAMP)\b", 1),
    ("Optimizer hint", r"/\*\+", 1),
    ("DUAL", r"\bFROM\s+DUAL\b", 1),
    ("MINUS", r"\bMINUS\b", 1),
    ("KEEP DENSE_RANK", r"\bKEEP\s*\(\s*DENSE_RANK\b", 4),
    ("PIVOT / UNPIVOT", r"\b(UN)?PIVOT\s*\(", 4),
    ("LISTAGG", r"\bLISTAGG\s*\(", 2),
    ("REGEXP_* functions", r"\bREGEXP_(LIKE|SUBSTR|REPLACE|INSTR|COUNT)\s*\(", 2),
    ("ADD_MONTHS / MONTHS_BETWEEN / LAST_DAY", r"\b(ADD_MONTHS|MONTHS_BETWEEN|LAST_DAY|NEXT_DAY)\s*\(", 2),
    ("TRUNC", r"\bTRUNC\s*\(", 1),
    ("TO_CHAR / TO_DATE / TO_NUMBER", r"\bTO_(CHAR|DATE|NUMBER|TIMESTAMP)\s*\(", 1),
    ("INSTR / SUBSTR", r"\b(INSTR|SUBSTR)\s*\(", 0),
    ("FOR UPDATE SKIP LOCKED / NOWAIT", r"\bFOR\s+UPDATE\b", 1),
    ("INTERVAL literal", r"\bINTERVAL\s*'", 1),
    ("Empty-string comparison", r"(=|<>|!=)\s*''", 2),
    ("ROWID", r"\bROWID\b", 3),
    ("Database link (@)", r"\b\w+@\w+\b(?=\s*(,|\bWHERE\b|\bON\b|\)|$))", 4),
    ("Oracle supplied package (DBMS_/UTL_)", r"\b(DBMS|UTL)_\w+", 5),
    ("PL/SQL package", r"\bCREATE\s+(OR\s+REPLACE\s+)?PACKAGE\b", 5),
    ("PRAGMA AUTONOMOUS_TRANSACTION", r"\bPRAGMA\s+AUTONOMOUS_TRANSACTION\b", 5),
    ("BULK COLLECT / FORALL", r"\bBULK\s+COLLECT\b|\bFORALL\b", 4),
    ("%TYPE / %ROWTYPE", r"%\s*(ROW)?TYPE\b", 1),
    ("SQL%ROWCOUNT / cursor attributes", r"\b(SQL|\w+)%\s*(ROWCOUNT|FOUND|NOTFOUND|ISOPEN)\b", 2),
    ("RAISE_APPLICATION_ERROR", r"\bRAISE_APPLICATION_ERROR\b", 2),
    ("RETURNING ... INTO", r"\bRETURNING\b[^;]*\bINTO\b", 3),
    ("PL/SQL collection types", r"\bINDEX\s+BY\b|\bTABLE\s+OF\b|\bVARRAY\b", 3),
    ("EXCEPTION handlers", r"\bEXCEPTION\s+WHEN\b|\bWHEN\s+(NO_DATA_FOUND|TOO_MANY_ROWS|OTHERS)\b", 2),
    ("Oracle data types (VARCHAR2/NUMBER/CLOB)", r"\b(VARCHAR2|NVARCHAR2|NUMBER|CLOB|BLOB|RAW|LONG)\b\s*(\(|,|\)|$|\s)", 1),
]
_COMPILED = [(label, re.compile(rx, re.I | re.M), w) for label, rx, w in _RULES]

_STR = re.compile(r"'(?:[^']|'')*'")


def mask_strings(sql: str) -> str:
    """Blank out the contents of string literals so keywords inside them do not match."""
    return _STR.sub(lambda m: "'" + "x" * (len(m.group(0)) - 2) + "'", sql)


def detect(sql: str, kind: str) -> tuple[list[str], int]:
    masked = mask_strings(sql)
    found: list[str] = []
    weight = 0
    for label, rx, w in _COMPILED:
        target = sql if label == "Empty-string comparison" else masked
        if rx.search(target):
            if label.startswith("Oracle data types") and kind != "ddl" and kind != "plsql":
                continue
            found.append(label)
            weight += w
    if kind == "plsql":
        weight += 5
    return found, weight


def tier_for(kind: str, weight: int) -> str:
    if kind == "plsql" or weight >= 5:
        return "hard"
    if weight >= 2:
        return "moderate"
    return "trivial"
