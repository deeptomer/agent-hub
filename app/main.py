"""FastAPI entry point: flow catalogue, run lifecycle, live event stream (SSE) and report downloads."""
from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.core import registry
from app.core.events import store
from app.core import dialects
from app.core.llm import PROVIDERS, check_connection, check_copilot, copilot_token_problem
from app.flows.oracle_pg import flow as _flows  # noqa: F401  (registers the flows)
from app.flows.oracle_pg.report import to_html, to_markdown
from app.flows.oracle_pg.sandbox import cleanup_stale_schemas

_TOKEN_OK = re.compile(r"^[A-Za-z0-9_\-.=+/]{8,300}$")
_MODEL_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,59}$")  # Copilot model ids vary by plan, so shape-check only


def _check_model_and_key(provider: str, key: str, model: str) -> None:
    if key and not _TOKEN_OK.match(key):
        raise HTTPException(400, "That does not look like an API key (no spaces, up to 300 characters)")
    if provider == "copilot":
        if key and (problem := copilot_token_problem(key)):
            raise HTTPException(400, problem)
        if model and not _MODEL_OK.match(model):
            raise HTTPException(400, "Unknown model choice")
    elif model and model not in settings.model_choices:
        raise HTTPException(400, "Unknown model choice")


def _provider(value: str) -> str:
    value = (value or "").strip().lower() or settings.llm_provider
    if value not in PROVIDERS:
        raise HTTPException(400, "Unknown AI provider")
    return value


def _server_key(provider: str) -> str | None:
    return settings.copilot_token if provider == "copilot" else settings.anthropic_api_key
_checks: dict[str, list[float]] = {}
STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Data Base Converter", version="1.0")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.on_event("startup")
def _startup() -> None:
    n = cleanup_stale_schemas(settings.database_url)
    if n:
        print(f"cleaned {n} stale sandbox schema(s)")


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "time": time.time()}


@app.get("/api/config")
def config() -> dict:
    return {
        "llm_configured": bool(settings.anthropic_api_key),
        "dialects": dialects.public(),
        "default_provider": settings.llm_provider,
        "server_keys": {"anthropic": bool(settings.anthropic_api_key), "copilot": bool(settings.copilot_token)},
        "copilot_model": settings.copilot_model,
        "database_configured": bool(settings.database_url),
        "access_code_required": bool(settings.access_code),
        "models": {"orchestrator": settings.model_orchestrator, "converter": settings.model_converter,
                   "reviewer": settings.model_reviewer, "critic": settings.model_critic},
        "model_choices": settings.model_choices,
        "providers": [{"id": "server", "label": "Server key (set in Render)", "available": bool(settings.anthropic_api_key)},
                      {"id": "own", "label": "My own Anthropic API key", "available": True}],
        "limits": {"upload_mb": settings.max_upload_bytes // (1024 * 1024), "max_statements": settings.max_statements,
                   "max_repair_attempts": settings.max_repair_attempts},
    }


@app.get("/api/flows")
def flows() -> list[dict]:
    return [f.public() for f in registry.FLOWS.values()]


@app.get("/api/sample")
def sample_files() -> list[dict]:
    root = settings.sample_app_dir
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in (".java", ".xml", ".sql", ".md"):
            out.append({"path": str(p.relative_to(root)), "content": p.read_text("utf-8")})
    return out


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")


@app.post("/api/runs")
async def create_run(
    request: Request,
    flow_id: str = Form(...),
    source: str = Form("sample"),
    github_url: str = Form(""),
    sql: str = Form(""),
    schema_sql: str = Form(""),
    access_code: str = Form(""),
    llm_key: str = Form(""),
    llm_model: str = Form(""),
    llm_provider: str = Form(""),
    source_db: str = Form(dialects.DEFAULT_SOURCE),
    target_db: str = Form(dialects.DEFAULT_TARGET),
    github_token: str = Form(""),
    no_ai: str = Form(""),
    file: UploadFile | None = File(None),
) -> JSONResponse:
    flow = registry.FLOWS.get(flow_id)
    if flow is None:
        raise HTTPException(404, "Unknown flow")
    ip = _client_ip(request)
    if store.active_count() >= settings.max_concurrent_runs:
        raise HTTPException(429, "The server is busy with other runs. Try again in a minute.")
    if store.recent_for_ip(ip) >= settings.runs_per_hour_per_ip:
        raise HTTPException(429, "Run limit reached for this hour.")

    source_db, target_db = source_db.strip().lower() or dialects.DEFAULT_SOURCE, target_db.strip().lower() or dialects.DEFAULT_TARGET
    if problem := dialects.validate_pair(source_db, target_db):
        raise HTTPException(400, problem)
    if flow_id == "oracle-java-migration" and source in ("sample", "sample2") and source_db != "oracle":
        raise HTTPException(400, "The bundled sample projects use Oracle. Upload your own project or choose Oracle as the source database.")
    inputs: dict = {"source": source, "github_url": github_url, "sql": sql, "schema_sql": schema_sql,
                    "source_db": source_db, "target_db": target_db}
    if flow_id == "oracle-java-migration" and source == "upload":
        if file is None:
            raise HTTPException(400, "Choose a .zip file to upload")
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(413, f"Upload is larger than {settings.max_upload_bytes // (1024 * 1024)} MB")
        inputs["upload_bytes"], inputs["filename"] = data, file.filename or "upload.zip"
    if flow_id == "oracle-java-migration" and source == "github" and not github_url.strip():
        raise HTTPException(400, "Enter a GitHub repository URL")
    if flow_id == "sql-snippet-converter" and not sql.strip():
        raise HTTPException(400, "Paste an Oracle SQL statement or PL/SQL block")

    llm_key, github_token, llm_model = llm_key.strip(), github_token.strip(), llm_model.strip()
    if no_ai:
        llm_key = ""
    provider = _provider(llm_provider)
    _check_model_and_key(provider, llm_key, llm_model)
    if github_token and not _TOKEN_OK.match(github_token):
        raise HTTPException(400, "That does not look like a GitHub token")
    if github_token:
        inputs["github_token"] = github_token

    # A caller who brings their own key spends their own money, so no access code is needed. Otherwise, with an access
    # code configured, only callers who know it can use the server's key; others still get the rules engine.
    use_llm = not no_ai
    if use_llm and settings.access_code and not llm_key:
        use_llm = hmac.compare_digest(access_code.encode(), settings.access_code.encode())

    ai_on = bool(llm_key or (use_llm and _server_key(provider)))
    source_label = ("your own " + ("GitHub token" if provider == "copilot" else "key")) if llm_key else "the server key"
    default_model = settings.copilot_model if provider == "copilot" else "per-agent defaults"
    run = store.create(flow_id, ip)
    run.emit("Platform", f"AI assist: on ({'GitHub Copilot' if provider == 'copilot' else 'Claude'}; {source_label}; model {llm_model or default_model})" if ai_on
             else "AI assist: off (rules-only run)", "info")
    registry.start(flow, run, inputs, use_llm=use_llm, llm_key=llm_key or None, llm_model=llm_model or None, llm_provider=provider)
    return JSONResponse({"run_id": run.id, "ai_assist": ai_on, "ai_source": ("user" if llm_key else "server") if ai_on else None,
                         "ai_provider": provider if ai_on else None})


@app.post("/api/llm/check")
async def llm_check(request: Request, llm_key: str = Form(""), llm_model: str = Form(""), llm_provider: str = Form("")) -> dict:
    """'Test connection' button. The key is used for one cheap check and discarded."""
    ip = _client_ip(request)
    now = time.time()
    hits = [t for t in _checks.get(ip, []) if now - t < 3600]
    if len(hits) >= 20:
        raise HTTPException(429, "Too many connection checks this hour")
    _checks[ip] = hits + [now]
    provider = _provider(llm_provider)
    key, model = llm_key.strip(), llm_model.strip()
    _check_model_and_key(provider, key, model)
    key = key or (_server_key(provider) or "")
    if provider == "copilot":
        if not key:
            return {"ok": False, "message": "No token: paste your own GitHub token or ask the owner to set COPILOT_GITHUB_TOKEN on the server"}
        ok, msg, models = await asyncio.to_thread(check_copilot, key, model or settings.copilot_model)
        return {"ok": ok, "message": msg, "model": model or settings.copilot_model, "models": models[:60]}
    model = model or settings.model_converter
    if not key:
        return {"ok": False, "message": "No key: paste your own key or ask the owner to set ANTHROPIC_API_KEY on the server"}
    ok, msg = await asyncio.to_thread(check_connection, key, model)
    return {"ok": ok, "message": msg, "model": model}


def _run_or_404(run_id: str):
    run = store.get(run_id)
    if run is None:
        raise HTTPException(404, "Run not found (runs are kept in memory and cleared on restart)")
    return run


@app.get("/api/runs/{run_id}")
def run_status(run_id: str) -> dict:
    r = _run_or_404(run_id)
    return {**r.summary(), "has_result": r.result is not None, "event_count": len(r.events)}


@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str, request: Request, start: int = 0) -> StreamingResponse:
    run = _run_or_404(run_id)

    async def gen():
        i, last_ping = start, time.time()
        while True:
            for e in run.events_since(i):
                yield f"id: {e.seq}\ndata: {json.dumps(e.to_dict())}\n\n"
                i = e.seq + 1
            if run.status in ("done", "error") and not run.events_since(i):
                yield f"event: end\ndata: {json.dumps({'status': run.status, 'error': run.error})}\n\n"
                return
            if await request.is_disconnected():
                return
            if time.time() - last_ping > 15:
                yield ": ping\n\n"
                last_ping = time.time()
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/runs/{run_id}/result")
def run_result(run_id: str) -> JSONResponse:
    r = _run_or_404(run_id)
    if r.result is None:
        raise HTTPException(409, "Run has not finished" if r.status in ("queued", "running") else (r.error or "No result"))
    return JSONResponse(r.result)


@app.get("/api/runs/{run_id}/report")
def run_report(run_id: str, format: str = "html"):
    r = _run_or_404(run_id)
    if r.result is None:
        raise HTTPException(409, "Run has not finished")
    name = f"migration-report-{run_id}"
    if format == "json":
        return JSONResponse(r.result, headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
    if format in ("md", "markdown"):
        return PlainTextResponse(to_markdown(r.result), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{name}.md"'})
    return HTMLResponse(to_html(r.result), headers={"Content-Disposition": f'attachment; filename="{name}.html"'})
