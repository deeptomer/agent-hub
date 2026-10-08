import email.message
import urllib.error

import pytest

from app.core.events import Run
from app.core.registry import FLOWS, RunContext
import app.flows.oracle_pg.flow  # noqa: F401
from app.flows.oracle_pg.orchestrator import Plan, default_plan, sanitize_plan
from tests.conftest import FakeLLM
from tests.golden_conversions import KEEP, answers

INV = {"unassembled_sql_fragments": 3, "claude_available": True}


def _ctx(tmp_path, llm, source="sample"):
    return RunContext(run=Run("oracle-java-migration"), inputs={"source": source}, llm=llm, workdir=tmp_path)


def _events(ctx):
    return [e.message for e in ctx.run.events]


# ---------------------------------------------------------------- plan validation (pure)
def test_plan_is_clamped_and_cannot_exceed_guardrails(monkeypatch):
    monkeypatch.setenv("MAX_REPAIR_ATTEMPTS", "2")
    p = sanitize_plan({"run_code_reader": True, "review_depth": "banana", "run_critic": True, "max_repairs": 99,
                       "focus": ["a" * 300, "b", "c", "d", "e"], "rationale": "x" * 900}, INV)
    assert p.review_depth == "non_trivial" and p.max_repairs == 2 and len(p.focus) == 4
    assert all(len(f) <= 90 for f in p.focus) and len(p.rationale) <= 500 and p.source == "orchestrator"


def test_plan_cannot_use_claude_when_unavailable_and_falls_back_on_garbage():
    p = sanitize_plan({"run_code_reader": True, "run_critic": True, "review_depth": "all", "max_repairs": 1, "rationale": "r"},
                      {"unassembled_sql_fragments": 0, "claude_available": False})
    assert p.run_critic is False and p.run_code_reader is False
    assert sanitize_plan("not a dict", INV).source == "default"
    assert default_plan({"unassembled_sql_fragments": 0, "claude_available": False}).run_critic is False


# ---------------------------------------------------------------- the supervisor graph
def test_default_plan_without_llm_and_trace(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    llm = FakeLLM()
    llm.available = False
    rep = FLOWS["oracle-java-migration"].runner(_ctx(tmp_path, llm))
    o = rep["meta"]["orchestration"]
    assert o["plan"]["source"] == "default"
    steps = [t["step"] for t in o["trace"]]
    assert steps[0] == "plan" and steps[-1] == "report" and "critic" not in steps


def test_orchestrator_plan_changes_what_runs(pg_dsn, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_dsn)
    plan = {"run_code_reader": False, "review_depth": "rules_only", "run_critic": False, "max_repairs": 0,
            "focus": ["date arithmetic in reports"], "rationale": "Mostly trivial; keep it cheap."}
    llm = FakeLLM(answers=answers(), tool_answers={"submit_plan": plan})
    ctx = _ctx(tmp_path, llm)
    rep = FLOWS["oracle-java-migration"].runner(ctx)
    assert rep["meta"]["orchestration"]["plan"]["review_depth"] == "rules_only"
    assert not any(c[1] == "submit_review" for c in llm.calls)  # the plan removed the Claude reviewer
    assert any("Mostly trivial" in m for m in _events(ctx))
    assert "critic" not in [t["step"] for t in rep["meta"]["orchestration"]["trace"]]


def test_critic_round_fixes_a_failure_with_a_hint(pg_dsn, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_dsn)

    def keep(user):
        good = "<critic_hint>" in user
        return {"postgres_sql": KEEP if good else "SELECT FROM WHERE", "explanation": "x", "assumptions": [], "needs_manual_review": False}

    seen = {}

    def triage(user):
        ids = [l.split('"')[3] for l in user.splitlines() if '"id"' in l]
        seen["failing"] = ids
        return {"retry_ids": ids + ["S999"], "rationale": "KEEP is fixable"}  # S999 does not exist: must be ignored

    llm = FakeLLM(answers={**answers(), "KEEP (DENSE_RANK": keep},
                  tool_answers={"submit_triage": triage,
                                "submit_critique": {"diagnosis": "ARRAY_AGG needed", "instruction": "Use (ARRAY_AGG(col ORDER BY ..))[1]",
                                                    "give_up": False},
                                "submit_plan": {"run_code_reader": False, "review_depth": "non_trivial", "run_critic": True,
                                                "max_repairs": 0, "rationale": "retry via critic"}})
    rep = FLOWS["oracle-java-migration"].runner(_ctx(tmp_path, llm))
    by = {s["label"]: s for s in rep["statements"]}
    keep_stmt = next(s for s in rep["statements"] if "KEEP" in s["oracle_sql"] and "DENSE_RANK" in s["oracle_sql"])
    assert seen["failing"], "triage never saw the failing statement"
    assert keep_stmt["validation"]["status"] in ("ok", "inconclusive")
    assert any("Critic" in n for n in keep_stmt["notes"])
    assert any(t["step"] == "triage" for t in rep["meta"]["orchestration"]["trace"])
    assert "critic_hint" not in keep_stmt["meta"]  # the hint is consumed, not leaked into the report


def test_critic_can_hand_back_to_a_human(pg_dsn, tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", pg_dsn)
    bad = {"postgres_sql": "SELECT FROM WHERE", "explanation": "", "needs_manual_review": False}
    llm = FakeLLM(answers={**answers(), "KEEP (DENSE_RANK": bad},
                  tool_answers={"submit_triage": lambda u: {"retry_ids": [l.split('"')[3] for l in u.splitlines() if '"id"' in l],
                                                            "rationale": "try"},
                                "submit_critique": {"diagnosis": "needs a business decision", "instruction": "", "give_up": True,
                                                    "give_up_reason": "no safe equivalent"},
                                "submit_plan": {"run_code_reader": False, "review_depth": "rules_only", "run_critic": True,
                                                "max_repairs": 0, "rationale": "r"}})
    rep = FLOWS["oracle-java-migration"].runner(_ctx(tmp_path, llm))
    keep_stmt = next(s for s in rep["statements"] if "DENSE_RANK" in s["oracle_sql"])
    assert keep_stmt["validation"]["status"] == "failed"
    assert any("needs a human" in n for n in keep_stmt["notes"])


# ---------------------------------------------------------------- credentials
def test_user_key_is_redacted_from_errors(monkeypatch):
    from app.core import llm as llm_mod

    class Boom:
        class messages:  # noqa: N801
            @staticmethod
            def create(**kw):
                raise RuntimeError("401 bad key sk-ant-SECRET123456")

    monkeypatch.setattr(llm_mod.anthropic, "Anthropic", lambda **kw: Boom())
    llm = llm_mod.LLM(enabled=False, api_key="sk-ant-SECRET123456", model_override="claude-haiku-4-5-20251001")
    assert llm.available and llm.key_source == "user"  # a caller's own key works even if the server has no key / access code
    assert llm.call_tool(agent="t", model="m", system="s", user="u", tool_name="x", tool_description="d", schema={}) is None
    assert "SECRET" not in (llm.last_error or "") and "[redacted-key]" in llm.last_error
    assert "SECRET" not in str(llm.describe())


def test_model_override_wins(monkeypatch):
    from app.core import llm as llm_mod
    seen = {}

    class Resp:
        content = []
        usage = None

    class Client:
        class messages:  # noqa: N801
            @staticmethod
            def create(**kw):
                seen.update(kw)
                return Resp()

    monkeypatch.setattr(llm_mod.anthropic, "Anthropic", lambda **kw: Client())
    llm = llm_mod.LLM(enabled=True, api_key="sk-ant-abcdefgh", model_override="claude-opus-5-5")
    llm.call_tool(agent="t", model="claude-sonnet-5-5", system="s", user="u", tool_name="x", tool_description="d", schema={})
    assert seen["model"] == "claude-opus-5-5"


def test_api_credentials_and_model_validation(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from app.core import registry
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ACCESS_CODE", "s3cret")
    captured = {}
    monkeypatch.setattr(registry, "start", lambda flow, run, inputs, use_llm=True, llm_key=None, llm_model=None, llm_provider=None:
                        captured.update(use_llm=use_llm, llm_key=llm_key, llm_model=llm_model, inputs=inputs))
    from app.main import app
    c = TestClient(app)
    base = {"flow_id": "sql-snippet-converter", "sql": "SELECT 1 FROM DUAL"}
    assert c.post("/api/runs", data={**base, "llm_key": "has spaces in it"}).status_code == 400
    assert c.post("/api/runs", data={**base, "llm_key": "sk-ant-abcdefgh", "llm_model": "gpt-evil"}).status_code == 400
    r = c.post("/api/runs", data={**base, "llm_key": "sk-ant-abcdefgh", "llm_model": "claude-opus-5-5"})
    assert r.status_code == 200 and r.json()["ai_assist"] is True and r.json()["ai_source"] == "user"
    assert captured["llm_key"] == "sk-ant-abcdefgh" and captured["use_llm"] is True and captured["llm_model"] == "claude-opus-5-5"
    ev = [e.message for e in __import__("app.core.events", fromlist=["store"]).store.get(r.json()["run_id"]).events]
    assert not any("sk-ant" in m for m in ev)  # the key never reaches the event log
    r2 = c.post("/api/runs", data=base)  # no key, no code: rules-only
    assert r2.json()["ai_assist"] is False and captured["use_llm"] is False
    from app.core.events import store
    for run in list(store._runs.values()):  # start() was mocked, so close the runs it never ran
        if run.status in ("queued", "running"):
            run.status = "done"


def test_connection_check_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    import app.main as m
    monkeypatch.setattr(m, "check_connection", lambda key, model: (key.startswith("sk-ant"), "msg"))
    c = TestClient(m.app)
    assert c.post("/api/llm/check", data={"llm_key": "sk-ant-abcdefgh"}).json()["ok"] is True
    assert c.post("/api/llm/check", data={"llm_key": "bad key!"}).status_code == 400
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert c.post("/api/llm/check", data={}).json()["ok"] is False


# ---------------------------------------------------------------- GitHub token
def _http302(location):
    h = email.message.Message()
    h["Location"] = location
    return urllib.error.HTTPError("https://api.github.com/x", 302, "Found", h, None)


def test_github_token_goes_to_api_host_only(monkeypatch):
    from app.core import security
    calls = []

    def fake_read(req, max_bytes, opener=None):
        calls.append((req.full_url, req.get_header("Authorization")))
        if opener is not None:
            raise _http302("https://codeload.github.com/o/r/legacy.zip/abc")
        return b"PK-fake"

    monkeypatch.setattr(security, "_read_limited", fake_read)
    assert security.fetch_github_zip("https://github.com/o/r", 1000, token="ghp_secrettoken") == b"PK-fake"
    assert calls[0][0].startswith("https://api.github.com/repos/o/r/zipball") and calls[0][1] == "Bearer ghp_secrettoken"
    assert calls[1][0].startswith("https://codeload.github.com/") and calls[1][1] is None  # token not forwarded


def test_github_redirect_to_other_host_is_refused(monkeypatch):
    from app.core import security

    def fake_read(req, max_bytes, opener=None):
        raise _http302("https://evil.example.com/steal")

    monkeypatch.setattr(security, "_read_limited", fake_read)
    with pytest.raises(security.UnsafeInput):
        security.fetch_github_zip("https://github.com/o/r", 1000, token="ghp_secrettoken")


def test_no_ai_switch_forces_rules_only_even_with_server_key(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from app.core import registry
    from app.core.events import store
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-serverkey")
    monkeypatch.delenv("ACCESS_CODE", raising=False)
    captured = {}
    monkeypatch.setattr(registry, "start", lambda flow, run, inputs, use_llm=True, llm_key=None, llm_model=None, llm_provider=None:
                        captured.update(use_llm=use_llm, llm_key=llm_key))
    from app.main import app
    r = TestClient(app).post("/api/runs", data={"flow_id": "sql-snippet-converter", "sql": "SELECT 1 FROM DUAL",
                                                "no_ai": "1", "llm_key": "sk-ant-abcdefgh"})
    assert r.json()["ai_assist"] is False and captured == {"use_llm": False, "llm_key": None}
    for run in list(store._runs.values()):
        if run.status in ("queued", "running"):
            run.status = "done"
