"""LLM wrapper with two interchangeable backends (Claude via the Anthropic API, GitHub Copilot via the Copilot SDK):
forced tool-use for structured output, usage tracking, graceful degradation."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
from typing import Any

from app.config import settings

try:  # the app still runs (rules-only) if the SDK or key is missing
    import anthropic
except Exception:  # pragma: no cover
    anthropic = None  # type: ignore


PROVIDERS = ("anthropic", "copilot")
COPILOT_TOKEN_PREFIXES = ("github_pat_", "gho_", "ghu_")  # ghp_ (classic PAT) is not supported by the Copilot runtime

# Only these variables reach the Copilot runtime process. Server secrets (ANTHROPIC_API_KEY, DATABASE_URL, ACCESS_CODE,
# other users' tokens) are deliberately not passed on; the token itself is handed over explicitly.
_COPILOT_ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
                     "NODE_EXTRA_CA_CERTS", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                     "COPILOT_CLI_PATH", "COPILOT_SKIP_CLI_DOWNLOAD", "XDG_CACHE_HOME")


def _copilot_importable() -> bool:
    try:
        import copilot  # noqa: F401
        return True
    except Exception:
        return False


def copilot_token_problem(token: str) -> str | None:
    """Reason a token cannot work with GitHub Copilot, or None."""
    if token.startswith("ghp_"):
        return ("Classic personal access tokens (ghp_...) are not supported by Copilot. Create a fine-grained token "
                "(github_pat_...) on your personal account with the 'Copilot Requests' permission.")
    if not token.startswith(COPILOT_TOKEN_PREFIXES):
        return "Expected a fine-grained token (github_pat_...) or an OAuth/App user token (gho_... / ghu_...)."
    return None


def _copilot_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _COPILOT_ENV_KEEP if k in os.environ}


def _is_auth_failure(text: str) -> bool:
    t = text.lower()
    return any(x in t for x in ("not authenticated", "unauthorized", "401", "403", "forbidden", "no copilot", "not entitled",
                                "subscription", "bad credentials", "authenticat"))


class _CopilotRunner:
    """One GitHub Copilot SDK client per run, living on its own asyncio loop in a daemon thread so that the synchronous
    agents (LangGraph worker threads) can call it. A fresh session is created per call, so agents never share context.
    Structured output works like it does for Claude: the model must answer through one declared tool whose JSON schema is
    the agent's schema; the tool handler captures the arguments. All built-in Copilot tools (shell, files, web) are
    switched off and every permission request is rejected: here Copilot is used as a language model, not as an agent."""

    def __init__(self, token: str) -> None:
        self._token = token
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._client = None
        self._tmp = tempfile.TemporaryDirectory(prefix="copilot-")
        self._guard = threading.Lock()

    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        with self._guard:
            if self._loop is None:
                self._loop = asyncio.new_event_loop()
                self._thread = threading.Thread(target=self._loop.run_forever, name="copilot-loop", daemon=True)
                self._thread.start()
            return self._loop

    def _run(self, coro, timeout: float):
        fut = asyncio.run_coroutine_threadsafe(coro, self._ensure_loop())
        try:
            return fut.result(timeout=timeout)
        except Exception:
            fut.cancel()
            raise

    async def _get_client(self):
        if self._client is None:
            from copilot import CopilotClient
            client = CopilotClient(github_token=self._token, use_logged_in_user=False, working_directory=self._tmp.name,
                                   log_level="error", env=_copilot_env())
            await client.start()
            self._client = client
        return self._client

    async def _ask(self, model: str, system: str, user: str, tool_name: str, tool_description: str,
                   schema: dict[str, Any], timeout: float) -> dict[str, Any] | None:
        from copilot import ToolSet
        from copilot.generated.rpc import PermissionDecisionReject
        from copilot.tools import Tool, ToolResult

        got: dict[str, Any] = {}

        async def capture(invocation):  # the model "answers" by calling this tool
            args = getattr(invocation, "arguments", None)
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = None
            if isinstance(args, dict) and "args" not in got:
                got["args"] = dict(args)
            return ToolResult(text_result_for_llm="Received. Do not call any other tool; reply with the single word done.")

        tool = Tool(name=tool_name, description=tool_description, parameters=schema, handler=capture,
                    skip_permission=True)
        client = await self._get_client()
        session = await client.create_session(
            on_permission_request=lambda req, inv: PermissionDecisionReject(feedback="Tools are disabled in this app"),
            model=model,
            tools=[tool],
            available_tools=ToolSet().add_custom(tool_name),
            system_message={"mode": "replace",
                            "content": system + "\n\nYou must give your answer by calling the tool `" + tool_name
                            + "` exactly once, with arguments that match its schema."},
            skip_custom_instructions=True,
            enable_config_discovery=False,
            enable_skills=False,
            infinite_sessions={"enabled": False},
            working_directory=self._tmp.name,
        )
        reply = None
        try:
            reply = await session.send_and_wait(user, timeout=timeout)
        finally:
            try:
                await session.disconnect()
            except Exception:
                pass
        if "args" in got:
            return got["args"]
        # Fallback: some models answer in plain JSON instead of calling the tool.
        text = getattr(getattr(reply, "data", None), "content", "") or ""
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                obj = json.loads(text[start:end + 1])
                return obj if isinstance(obj, dict) else None
            except ValueError:
                return None
        return None

    def ask(self, **kw) -> dict[str, Any] | None:
        timeout = kw["timeout"]
        return self._run(self._ask(**kw), timeout + 30)

    async def _stop(self) -> None:
        if self._client is not None:
            try:
                await self._client.stop()
            except Exception:
                pass
            self._client = None

    def close(self) -> None:
        loop = self._loop
        if loop is not None:
            try:
                asyncio.run_coroutine_threadsafe(self._stop(), loop).result(timeout=15)
            except Exception:
                pass
            loop.call_soon_threadsafe(loop.stop)
            self._loop = None
        try:
            self._tmp.cleanup()
        except Exception:
            pass


class LLM:
    """One LLM connection per run. `provider` is 'anthropic' (Claude, API key) or 'copilot' (GitHub Copilot SDK, GitHub
    token). Agents call `call_tool` and do not care which. The credential is either the caller's own (per-run, held only
    in memory, never stored, logged or returned) or the server's. `model_override` forces one model for every agent.
    """

    def __init__(self, enabled: bool = True, api_key: str | None = None, model_override: str | None = None,
                 provider: str | None = None) -> None:
        self._lock = threading.Lock()
        self.usage: dict[str, dict[str, int]] = {}
        self.last_error: str | None = None
        self.disabled = False
        self._client = None
        self._copilot: _CopilotRunner | None = None
        self.provider = provider if provider in PROVIDERS else settings.llm_provider
        self.model_override = model_override or None
        self._secret = (api_key or "").strip() or None
        self.key_source: str | None = None
        server_key = settings.copilot_token if self.provider == "copilot" else settings.anthropic_api_key
        key = self._secret or (server_key if enabled else None)
        if key and (enabled or self._secret):
            if self.provider == "copilot":
                if copilot_token_problem(key) is None and _copilot_importable():
                    self.key_source = "user" if self._secret else "server"
                    self._copilot = _CopilotRunner(key)
                else:
                    self.last_error = copilot_token_problem(key) or "The GitHub Copilot SDK is not installed on the server"
            elif anthropic is not None:
                self.key_source = "user" if self._secret else "server"
                self._client = anthropic.Anthropic(api_key=key, max_retries=2, timeout=90.0)
        self._key = key

    def _redact(self, text: str) -> str:
        return text.replace(self._key, "[redacted-key]") if self._key else text

    def describe(self) -> dict[str, Any]:
        return {"provider": self.provider, "key_source": self.key_source,
                "model": self.model_override or ("copilot default: " + settings.copilot_model if self.provider == "copilot"
                                                 else "per-agent defaults")}

    @property
    def available(self) -> bool:
        return (self._client is not None or self._copilot is not None) and not self.disabled

    def close(self) -> None:
        """Release the Copilot runtime process (no-op for Claude). Safe to call twice."""
        runner, self._copilot = self._copilot, None
        if runner is not None:
            runner.close()

    def _track(self, agent: str, model: str, usage: Any = None, tokens: tuple[int, int] | None = None) -> None:
        with self._lock:
            u = self.usage.setdefault(agent, {"calls": 0, "input_tokens": 0, "output_tokens": 0})
            u["calls"] += 1
            if tokens is not None:  # Copilot reports no token counts; these are estimates (about 4 characters a token)
                u["input_tokens"] += tokens[0]
                u["output_tokens"] += tokens[1]
            else:
                u["input_tokens"] += getattr(usage, "input_tokens", 0) or 0
                u["output_tokens"] += getattr(usage, "output_tokens", 0) or 0
            u["model"] = model  # type: ignore[assignment]

    def call_tool(self, *, agent: str, model: str, system: str, user: str, tool_name: str,
                  tool_description: str, schema: dict[str, Any], max_tokens: int = 4096) -> dict[str, Any] | None:
        """Ask Claude to answer by calling one tool whose input_schema is `schema`. Returns the tool input or None."""
        if not self.available:
            return None
        if self._copilot is not None:
            return self._call_copilot(agent, system, user, tool_name, tool_description, schema)
        model = self.model_override or model
        try:
            resp = self._client.messages.create(  # type: ignore[union-attr]
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                tools=[{"name": tool_name, "description": tool_description, "input_schema": schema}],
                tool_choice={"type": "tool", "name": tool_name},
            )
            self._track(agent, model, resp.usage)
            for block in resp.content:
                if getattr(block, "type", "") == "tool_use" and block.name == tool_name:
                    return dict(block.input)
            self.last_error = "model returned no tool call"
            return None
        except Exception as exc:  # network, rate limit, auth, bad model name...
            self.last_error = self._redact(f"{type(exc).__name__}: {str(exc)[:300]}")
            name = type(exc).__name__
            if name in ("AuthenticationError", "PermissionDeniedError", "NotFoundError"):
                self.disabled = True  # do not hammer the API with a bad key / model
            return None

    def _call_copilot(self, agent: str, system: str, user: str, tool_name: str, tool_description: str,
                      schema: dict[str, Any]) -> dict[str, Any] | None:
        model = self.model_override or settings.copilot_model
        try:
            out = self._copilot.ask(model=model, system=system, user=user, tool_name=tool_name,  # type: ignore[union-attr]
                                    tool_description=tool_description, schema=schema, timeout=settings.copilot_timeout)
        except Exception as exc:  # timeout, runtime crash, rate limit, no entitlement...
            msg = f"{type(exc).__name__}: {str(exc)[:300]}"
            self.last_error = self._redact(msg)
            if _is_auth_failure(msg):
                self.disabled = True  # bad or unentitled token: stop retrying for the rest of the run
            return None
        self._track(agent, model, tokens=((len(system) + len(user)) // 4, len(json.dumps(out)) // 4 if out else 0))
        if out is None:
            self.last_error = "Copilot returned no structured answer"
        return out

    def usage_summary(self) -> dict[str, Any]:
        with self._lock:
            total_in = sum(u["input_tokens"] for u in self.usage.values())
            total_out = sum(u["output_tokens"] for u in self.usage.values())
            calls = sum(u["calls"] for u in self.usage.values())
            return {"provider": self.provider, "tokens_estimated": self.provider == "copilot",
                    "calls": calls, "input_tokens": total_in, "output_tokens": total_out,
                    "by_agent": {k: dict(v) for k, v in self.usage.items()}}


def check_copilot(token: str, model: str) -> tuple[bool, str, list[str]]:
    """Preflight for Copilot: start the runtime, check the token, list the models this account can use. No prompt is sent."""
    problem = copilot_token_problem(token)
    if problem:
        return False, problem, []
    if not _copilot_importable():
        return False, "The GitHub Copilot SDK is not installed on the server", []
    runner = _CopilotRunner(token)
    try:
        async def probe():
            client = await runner._get_client()
            status = await client.get_auth_status()
            if not getattr(status, "isAuthenticated", False):
                return False, "GitHub rejected the token: " + str(getattr(status, "statusMessage", "not authenticated")), []
            models = [str(getattr(m, "id", "")) for m in await client.list_models()]
            models = [m for m in models if m]
            who = getattr(status, "login", None)
            if model and model != "auto" and models and model not in models:
                return False, f"Signed in{' as ' + who if who else ''}, but the model '{model}' is not available to this account", models
            return True, f"Token accepted{' for ' + who if who else ''}; {len(models)} model(s) available", models
        return runner._run(probe(), 60)
    except Exception as exc:
        msg = f"{type(exc).__name__}: {str(exc)[:200]}"
        return False, ("Not authenticated: check the token and that its account has Copilot access" if _is_auth_failure(msg) else msg).replace(token, "[redacted-key]"), []
    finally:
        runner.close()


def check_connection(api_key: str, model: str) -> tuple[bool, str]:
    """Cheap preflight for the 'Test connection' button: one 1-token call. Never echoes the key."""
    if anthropic is None:
        return False, "The Anthropic SDK is not installed on the server"
    try:
        client = anthropic.Anthropic(api_key=api_key, max_retries=0, timeout=20.0)
        client.messages.create(model=model, max_tokens=1, messages=[{"role": "user", "content": "ping"}])
        return True, "Key accepted and model reachable"
    except Exception as exc:
        name = type(exc).__name__
        hint = {"AuthenticationError": "The key was rejected", "PermissionDeniedError": "The key has no access to this model",
                "NotFoundError": "The model name was not found for this key", "RateLimitError": "Rate limited; the key works"}.get(name)
        msg = hint or f"{name}: {str(exc)[:160]}"
        return name == "RateLimitError", msg.replace(api_key, "[redacted-key]")
