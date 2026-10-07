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
from app.core.events import Run
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


def start(flow: FlowDef, run: Run, inputs: dict[str, Any], use_llm: bool = True) -> None:
    """Run a flow on a background thread; never raises into the caller."""
    wd = settings.data_dir / "runs" / run.id
    wd.mkdir(parents=True, exist_ok=True)
    ctx = RunContext(run=run, inputs=inputs, llm=LLM(enabled=use_llm), workdir=wd)

    def job() -> None:
        run.status = "running"
        run.emit("Platform", f"Flow '{flow.title}' started", "stage")
        try:
            run.result = flow.runner(ctx)
            run.status = "done"
            run.emit("Platform", "Run complete", "ok")
        except Exception as exc:  # surface a clean error, keep the traceback in server logs
            traceback.print_exc()
            run.error = f"{type(exc).__name__}: {str(exc)[:300]}"
            run.status = "error"
            run.emit("Platform", f"Run failed: {run.error}", "error")
        finally:
            run.finished = time.time()

    _executor.submit(job)
