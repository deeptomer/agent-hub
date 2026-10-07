# Agent Hub — Oracle → PostgreSQL migration agents

A small platform that hosts several agent *flows*. The first flow migrates the SQL of a Java application
from Oracle to PostgreSQL; the second converts a single pasted statement.

## How the migration flow works
1. **Intake** – sample app, uploaded zip (allow-listed files only) or a public GitHub URL.
2. **Discover** – finds SQL in JDBC string code, MyBatis XML, JPA native queries, .sql and PL/SQL, plus app-level findings (driver, dialect, credentials).
3. **Rules engine** – sqlglot plus custom rewrites (ROWNUM paging, (+) joins, sequences, SYSDATE, date arithmetic, MERGE casts…). Deterministic and free.
4. **Claude agent** – only for what rules cannot do (CONNECT BY, KEEP DENSE_RANK, PIVOT, PL/SQL packages). Forced JSON tool output.
5. **Validate** – every result runs on a real PostgreSQL sandbox (EXPLAIN only, rolled back, per-run schema). Errors go back to Claude for up to 2 repairs.
6. **Review + report** – semantic risks a green plan cannot show (''=NULL, ROWNUM before ORDER BY…), confidence per statement, effort estimate, downloadable report.

## Run locally
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=...        # optional: without it the app runs rules-only
    export DATABASE_URL=postgresql://user:pw@localhost:5432/db   # optional: syntax-only without it
    uvicorn app.main:app --reload
    pytest                              # needs TEST_DATABASE_URL for the Postgres-backed tests

## Deploy on Render
1. Push this repo to GitHub.
2. Render → New → **Blueprint** → select the repo (uses `render.yaml`).
3. In the service's Environment tab set `ANTHROPIC_API_KEY` (and optionally `ACCESS_CODE`).
4. Open the URL; run the sample app.

Notes: free web services sleep after ~15 min idle (first request takes ~50 s — open it before your slot);
the free Postgres database expires after 30 days.

## Configuration
`ANTHROPIC_API_KEY`, `MODEL_CONVERTER`, `MODEL_REVIEWER`, `DATABASE_URL`, `ACCESS_CODE`, `MAX_UPLOAD_MB`, `MAX_FILES`,
`MAX_STATEMENTS`, `LLM_CONCURRENCY`, `MAX_REPAIR_ATTEMPTS`, `MAX_CONCURRENT_RUNS`, `RUNS_PER_HOUR_PER_IP`.

## Adding another agent flow
Register a `FlowDef` in `app/core/registry.py` style (see `app/flows/oracle_pg/flow.py`); it appears in the UI automatically.
