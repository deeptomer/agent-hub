"""GitHub Copilot backend: token rules, provider plumbing, failure handling, credential hygiene. No network, no real Copilot."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from app.core import llm as llm_mod
from app.core.llm import LLM, copilot_token_problem

GOOD = "github_pat_" + "A" * 30


class FakeRunner:
    instances = []

    def __init__(self, token):
        self.token, self.calls, self.closed, self.raise_exc, self.answer = token, [], False, None, {"ok": True}
        FakeRunner.instances.append(self)

    def ask(self, **kw):
        self.calls.append(kw)
        if self.raise_exc:
            raise self.raise_exc
        return self.answer

    def close(self):
        self.closed = True


@pytest.fixture()
def fake_runner(monkeypatch):
    FakeRunner.instances.clear()
    monkeypatch.setattr(llm_mod, "_CopilotRunner", FakeRunner)
    monkeypatch.setattr(llm_mod, "_copilot_importable", lambda: True)
    return FakeRunner


def test_token_rules():
    assert copilot_token_problem("ghp_" + "a" * 36) and "fine-grained" in copilot_token_problem("ghp_" + "a" * 36)
    assert copilot_token_problem("sk-ant-abcdefgh")
    for ok in (GOOD, "gho_" + "a" * 20, "ghu_" + "a" * 20):
        assert copilot_token_problem(ok) is None


def test_copilot_call_returns_tool_input_and_tracks_usage(fake_runner, monkeypatch):
    monkeypatch.setenv("COPILOT_MODEL", "auto")
    llm = LLM(api_key=GOOD, provider="copilot")
    assert llm.available and llm.key_source == "user" and llm.provider == "copilot"
    out = llm.call_tool(agent="Converter", model="claude-sonnet-5-5", system="sys", user="usr", tool_name="submit",
                        tool_description="d", schema={"type": "object", "properties": {}})
    assert out == {"ok": True}
    call = fake_runner.instances[0].calls[0]
    assert call["model"] == "auto" and call["tool_name"] == "submit"  # Claude model names are never sent to Copilot
    u = llm.usage_summary()
    assert u["calls"] == 1 and u["tokens_estimated"] is True and u["provider"] == "copilot"
    assert llm.describe()["provider"] == "copilot"


def test_model_override_is_used(fake_runner):
    llm = LLM(api_key=GOOD, provider="copilot", model_override="gpt-5")
    llm.call_tool(agent="A", model="x", system="s", user="u", tool_name="t", tool_description="d", schema={})
    assert fake_runner.instances[0].calls[0]["model"] == "gpt-5"


def test_auth_failure_disables_and_redacts(fake_runner):
    llm = LLM(api_key=GOOD, provider="copilot")
    fake_runner.instances[0].raise_exc = RuntimeError(f"401 Unauthorized for {GOOD}")
    assert llm.call_tool(agent="A", model="x", system="s", user="u", tool_name="t", tool_description="d", schema={}) is None
    assert llm.disabled and not llm.available
    assert GOOD not in (llm.last_error or "") and "[redacted-key]" in llm.last_error
    assert len(fake_runner.instances[0].calls) == 1
    assert llm.call_tool(agent="A", model="x", system="s", user="u", tool_name="t", tool_description="d", schema={}) is None
    assert len(fake_runner.instances[0].calls) == 1  # no hammering after a bad token


def test_transient_error_does_not_disable(fake_runner):
    llm = LLM(api_key=GOOD, provider="copilot")
    fake_runner.instances[0].raise_exc = TimeoutError("took too long")
    assert llm.call_tool(agent="A", model="x", system="s", user="u", tool_name="t", tool_description="d", schema={}) is None
    assert llm.available


def test_classic_pat_is_refused_without_starting_a_runtime(fake_runner):
    llm = LLM(api_key="ghp_" + "a" * 36, provider="copilot")
    assert not llm.available and "fine-grained" in llm.last_error and not fake_runner.instances


def test_server_token_used_only_when_enabled(fake_runner, monkeypatch):
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", GOOD)
    assert LLM(enabled=True, provider="copilot").key_source == "server"
    assert not LLM(enabled=False, provider="copilot").available


def test_close_stops_runtime_once(fake_runner):
    llm = LLM(api_key=GOOD, provider="copilot")
    llm.close(); llm.close()
    assert fake_runner.instances[0].closed and not llm.available


def test_runtime_env_excludes_server_secrets(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "DATABASE_URL", "ACCESS_CODE", "COPILOT_GITHUB_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.setenv(k, "secret-value")
    env = llm_mod._copilot_env()
    assert "PATH" in env and not {"ANTHROPIC_API_KEY", "DATABASE_URL", "ACCESS_CODE", "COPILOT_GITHUB_TOKEN", "GITHUB_TOKEN"} & set(env)


def test_check_copilot_rejects_bad_tokens_without_network():
    ok, msg, models = llm_mod.check_copilot("ghp_" + "a" * 36, "auto")
    assert not ok and "fine-grained" in msg and models == []


# ---- API -----------------------------------------------------------------------------------------------------------
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    for k in ("ANTHROPIC_API_KEY", "COPILOT_GITHUB_TOKEN", "ACCESS_CODE", "LLM_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    from app.main import app
    return TestClient(app)


def _mock_start(monkeypatch):
    from app.core import registry
    seen = {}

    def fake_start(flow, run, inputs, **kw):
        seen.update(kw); seen["run"] = run
        run.status = "done"; run.finished = time.time()
    monkeypatch.setattr(registry, "start", fake_start)
    return seen


def test_api_copilot_run_passes_provider_and_token(client, monkeypatch):
    seen = _mock_start(monkeypatch)
    r = client.post("/api/runs", data={"flow_id": "sql-snippet-converter", "sql": "SELECT 1 FROM DUAL",
                                       "llm_provider": "copilot", "llm_key": GOOD, "llm_model": "gpt-5"})
    j = r.json()
    assert r.status_code == 200 and j["ai_assist"] and j["ai_provider"] == "copilot" and j["ai_source"] == "user"
    assert seen["llm_provider"] == "copilot" and seen["llm_key"] == GOOD and seen["llm_model"] == "gpt-5"
    events = " ".join(e["message"] if isinstance(e, dict) else str(e) for e in seen["run"].events)
    assert "GitHub Copilot" in events and GOOD not in events


@pytest.mark.parametrize("data,code", [
    ({"llm_provider": "copilot", "llm_key": "ghp_" + "a" * 36}, 400),
    ({"llm_provider": "copilot", "llm_key": GOOD, "llm_model": "bad model!"}, 400),
    ({"llm_provider": "openai", "llm_key": GOOD}, 400),
    ({"llm_provider": "anthropic", "llm_key": "sk-ant-abcdefgh", "llm_model": "gpt-5"}, 400),  # not a Claude choice
])
def test_api_rejects_bad_provider_inputs(client, monkeypatch, data, code):
    _mock_start(monkeypatch)
    r = client.post("/api/runs", data={"flow_id": "sql-snippet-converter", "sql": "SELECT 1 FROM DUAL", **data})
    assert r.status_code == code


def test_api_server_token_makes_ai_available_with_provider_default(client, monkeypatch):
    _mock_start(monkeypatch)
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", GOOD)
    cfg = client.get("/api/config").json()
    assert cfg["server_keys"] == {"anthropic": False, "copilot": True}
    r = client.post("/api/runs", data={"flow_id": "sql-snippet-converter", "sql": "SELECT 1 FROM DUAL", "llm_provider": "copilot"})
    assert r.json()["ai_assist"] is True and r.json()["ai_source"] == "server"
    r = client.post("/api/runs", data={"flow_id": "sql-snippet-converter", "sql": "SELECT 1 FROM DUAL", "llm_provider": "anthropic"})
    assert r.json()["ai_assist"] is False  # no Anthropic key configured


def test_api_check_endpoint_copilot(client, monkeypatch):
    monkeypatch.setattr("app.main.check_copilot", lambda t, m: (True, "Token accepted; 2 model(s) available", ["auto", "gpt-5"]))
    r = client.post("/api/llm/check", data={"llm_provider": "copilot", "llm_key": GOOD})
    assert r.json() == {"ok": True, "message": "Token accepted; 2 model(s) available", "model": "auto", "models": ["auto", "gpt-5"]}
    assert client.post("/api/llm/check", data={"llm_provider": "copilot"}).json()["ok"] is False
    assert client.post("/api/llm/check", data={"llm_provider": "copilot", "llm_key": "ghp_" + "a" * 36}).status_code == 400
