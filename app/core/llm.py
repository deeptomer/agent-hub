"""Thin Claude wrapper: forced tool-use for structured output, usage tracking, graceful degradation."""
from __future__ import annotations

import threading
from typing import Any

from app.config import settings

try:  # the app still runs (rules-only) if the SDK or key is missing
    import anthropic
except Exception:  # pragma: no cover
    anthropic = None  # type: ignore


class LLM:
    """One Claude connection per run. The key is either the caller's own (per-run, held only in memory, never stored,
    logged or returned) or the server's ANTHROPIC_API_KEY. `model_override` forces one model for every agent."""

    def __init__(self, enabled: bool = True, api_key: str | None = None, model_override: str | None = None) -> None:
        self._lock = threading.Lock()
        self.usage: dict[str, dict[str, int]] = {}
        self.last_error: str | None = None
        self.disabled = False
        self._client = None
        self.model_override = model_override or None
        self._secret = (api_key or "").strip() or None
        self.key_source: str | None = None
        key = self._secret or (settings.anthropic_api_key if enabled else None)
        if key and (enabled or self._secret) and anthropic is not None:
            self.key_source = "user" if self._secret else "server"
            self._client = anthropic.Anthropic(api_key=key, max_retries=2, timeout=90.0)
        self._key = key

    def _redact(self, text: str) -> str:
        return text.replace(self._key, "[redacted-key]") if self._key else text

    def describe(self) -> dict[str, Any]:
        return {"key_source": self.key_source, "model": self.model_override or "per-agent defaults"}

    @property
    def available(self) -> bool:
        return self._client is not None and not self.disabled

    def _track(self, agent: str, model: str, usage: Any) -> None:
        with self._lock:
            u = self.usage.setdefault(agent, {"calls": 0, "input_tokens": 0, "output_tokens": 0})
            u["calls"] += 1
            u["input_tokens"] += getattr(usage, "input_tokens", 0) or 0
            u["output_tokens"] += getattr(usage, "output_tokens", 0) or 0
            u["model"] = model  # type: ignore[assignment]

    def call_tool(self, *, agent: str, model: str, system: str, user: str, tool_name: str,
                  tool_description: str, schema: dict[str, Any], max_tokens: int = 4096) -> dict[str, Any] | None:
        """Ask Claude to answer by calling one tool whose input_schema is `schema`. Returns the tool input or None."""
        if not self.available:
            return None
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

    def usage_summary(self) -> dict[str, Any]:
        with self._lock:
            total_in = sum(u["input_tokens"] for u in self.usage.values())
            total_out = sum(u["output_tokens"] for u in self.usage.values())
            calls = sum(u["calls"] for u in self.usage.values())
            return {"calls": calls, "input_tokens": total_in, "output_tokens": total_out,
                    "by_agent": {k: dict(v) for k, v in self.usage.items()}}


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
