"""Flow registry: the platform runs any registered flow; the UI renders itself from this metadata."""
from __future__ import annotations

import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from app.config import settings
from app.core.events import Run, RunCancelled
from app.core.llm import LLM


@dataclass
class RunContext:
    run: Run
    inputs: dict[str, Any]
    llm: LLM
    workdir: Path

    def emit(self, agent: str, message: str, level: str = "info", **data: Any) -> None:
        self.run.emit(agent, message, level, **data)


@dataclass
class FlowDef:
    id: str
    title: str
    tagline: str
    description: str
    agents: list[dict[str, str]]
    inputs: list[dict[str, Any]]
    runner: Callable[[RunContext], dict[str, Any]]
    uses_llm: bool = True
    meta: dict[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "tagline": self.tagline, "description": self.description,
                "agents": self.agents, "inputs": self.inputs, "uses_llm": self.uses_llm}


FLOWS: dict[str, FlowDef] = {}
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="flow")


def register(flow: FlowDef) -> None:
    FLOWS[flow.id] = flow


def start(flow: FlowDef, run: Run, inputs: dict[str, Any], use_llm: bool = True, llm_key: str | None = None,
          llm_model: str | None = None, llm_provider: str | None = None) -> None:
    """Run a flow on a background thread; never raises into the caller."""
    wd = settings.data_dir / "runs" / run.id
    wd.mkdir(parents=True, exist_ok=True)
    ctx = RunContext(run=run, inputs=inputs, llm=LLM(enabled=use_llm, api_key=llm_key, model_override=llm_model, provider=llm_provider), workdir=wd)

    ctx.llm.cancel_check = run.check_cancel

    def job() -> None:
        if run.cancelled:  # stopped while still waiting for a free worker
            ctx.llm.close()
            return
        run.status = "running"
        run.log("Platform", f"Flow '{flow.title}' started", "stage")
        try:
            result = flow.runner(ctx)
            if run.cancelled:
                return  # finished a hair after Stop: the user asked to stop, so keep it stopped
            run.result = result
            run.status = "done"
            run.log("Platform", "Run complete", "ok")
        except RunCancelled:
            pass  # status is already "cancelled"; the sandbox schema is dropped by the flow's own finally block
        except Exception as exc:  # surface a clean error, keep the traceback in server logs
            traceback.print_exc()
            run.error = f"{type(exc).__name__}: {str(exc)[:300]}"
            if not run.cancelled:
                run.status = "error"
                run.log("Platform", f"Run failed: {run.error}", "error")
        finally:
            if not run.cancelled:
                run.finished = time.time()
            closer = getattr(ctx.llm, "close", None)
            if callable(closer):
                closer()  # stops the Copilot runtime process, if one was started

    _executor.submit(job)
