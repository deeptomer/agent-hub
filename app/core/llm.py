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
    def __init__(self, enabled: bool = True) -> None:
        self._lock = threading.Lock()
        self.usage: dict[str, dict[str, int]] = {}
        self.last_error: str | None = None
        self.disabled = False
        self._client = None
        key = settings.anthropic_api_key
        if enabled and key and anthropic is not None:
            self._client = anthropic.Anthropic(api_key=key, max_retries=2, timeout=90.0)

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
            self.last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
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
