# Agent Hub — Oracle → PostgreSQL migration agents

A small platform that hosts several agent *flows*. The first flow migrates the SQL of a Java application
from Oracle to PostgreSQL; the second converts a single pasted statement.

## How the migration flow works
1. **Intake** – a new project (uploaded zip with allow-listed files only, or a public GitHub URL) or one of two bundled demo apps.
2. **Discover + Code Reader** – finds SQL in JDBC string code, MyBatis XML, JPA native queries, .sql and PL/SQL, plus app-level findings (driver, dialect, credentials). The Code Reader profiles the project (build tool, frameworks) and flags SQL strings the extractor could not assemble (StringBuilder chains, String.format, helper methods). With Claude enabled it reads only those files and reconstructs the statements; each reconstruction must use names that really occur in the file, is marked as a risk, and runtime parts are planned with a placeholder and never reported better than 'inconclusive'.
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

## Agents and orchestration
A LangGraph **supervisor** routes the work. After every worker the **Orchestrator** node decides who runs next:
Discovery, Code Reader, Converter (schema, PL/SQL, queries), Validator, Risk Reviewer, Critic, Report.
With Claude available the Orchestrator agent also (1) writes a plan after discovery (use the Code Reader's AI part or not,
review depth, repair budget, what the Risk Reviewer should focus on) and (2) triages statements that still fail, so the
Critic agent only gets those worth another try. Plans are clamped in code (`orchestrator.py`): the model cannot disable
validation or exceed the repair cap. Without Claude, a deterministic default plan runs. The report shows the plan and a trace.

## Credentials and models
* **Server key** – `ANTHROPIC_API_KEY` on Render (optionally gated by `ACCESS_CODE`).
* **Your own key** – paste an Anthropic API key in the "AI connection" panel. It is sent with the run over HTTPS, held in
  memory only for that run, never stored, logged or put in a report; errors are redacted. No access code is needed because you pay.
* **No AI** – rules-only run.
* **Model** – pick one model for all agents, or leave the per-agent defaults (`MODEL_ORCHESTRATOR`, `MODEL_CONVERTER`,
  `MODEL_REVIEWER`, `MODEL_CRITIC`). Allowed choices: `MODEL_CHOICES`.
* **GitHub token** – optional, for private repositories only (fine-grained, read-only Contents). Sent to api.github.com only.
  GitHub tokens cannot be used for AI: GitHub Models was retired in July 2026.

## Configuration
`ANTHROPIC_API_KEY`, `MODEL_ORCHESTRATOR`, `MODEL_CONVERTER`, `MODEL_REVIEWER`, `MODEL_CRITIC`, `MODEL_CHOICES`, `DATABASE_URL`, `ACCESS_CODE`, `MAX_UPLOAD_MB`, `MAX_FILES`,
`MAX_STATEMENTS`, `LLM_CONCURRENCY`, `MAX_REPAIR_ATTEMPTS`, `MAX_CONCURRENT_RUNS`, `RUNS_PER_HOUR_PER_IP`.

## Adding another agent flow
Register a `FlowDef` in `app/core/registry.py` style (see `app/flows/oracle_pg/flow.py`); it appears in the UI automatically.
