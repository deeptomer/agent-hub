"""Run objects and a tiny in-memory run store. Flows emit events; the API streams them."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class RunCancelled(BaseException):
    """Raised inside a run when the user pressed Stop. It derives from BaseException on purpose: the many
    `except Exception` guards that keep one bad statement from killing a run must not swallow a cancellation."""


@dataclass
class Event:
    seq: int
    ts: float
    agent: str
    level: str  # info | ok | warn | error | stage
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "agent": self.agent, "level": self.level,
                "message": self.message, "data": self.data}


class Run:
    def __init__(self, flow_id: str, client_ip: str = "") -> None:
        self.id = uuid.uuid4().hex[:12]
        self.flow_id = flow_id
        self.client_ip = client_ip
        self.status = "queued"  # queued | running | done | error | cancelled
        self.cancel_event = threading.Event()
        self.created = time.time()
        self.finished: float | None = None
        self.events: list[Event] = []
        self.result: dict[str, Any] | None = None
        self.error: str | None = None
        self._lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise RunCancelled()

    def log(self, agent: str, message: str, level: str = "info", **data: Any) -> None:
        """Append an event without a cancellation check (platform bookkeeping)."""
        with self._lock:
            self.events.append(Event(len(self.events), time.time(), agent, level, message, data))

    def emit(self, agent: str, message: str, level: str = "info", **data: Any) -> None:
        """Flows call this constantly, so it doubles as the cooperative cancellation point."""
        self.check_cancel()
        self.log(agent, message, level, **data)

    def cancel(self) -> bool:
        """Stop the run. Returns False if it had already finished. The status flips at once so the UI can react;
        the worker thread stops at its next event or AI call."""
        with self._lock:
            if self.status in ("done", "error", "cancelled"):
                return False
            self.status = "cancelled"
            self.finished = time.time()
            self.cancel_event.set()
        self.log("Platform", "Run stopped by you", "warn")
        return True

    def events_since(self, index: int) -> list[Event]:
        with self._lock:
            return self.events[index:]

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "flow_id": self.flow_id, "status": self.status,
                "created": self.created, "finished": self.finished, "error": self.error}


class RunStore:
    def __init__(self, max_runs: int = 40) -> None:
        self._runs: dict[str, Run] = {}
        self._lock = threading.Lock()
        self._max = max_runs

    def create(self, flow_id: str, client_ip: str = "") -> Run:
        run = Run(flow_id, client_ip)
        with self._lock:
            self._runs[run.id] = run
            if len(self._runs) > self._max:
                oldest = sorted(self._runs.values(), key=lambda r: r.created)[: len(self._runs) - self._max]
                for r in oldest:
                    if r.status in ("done", "error", "cancelled"):
                        self._runs.pop(r.id, None)
        return run

    def get(self, run_id: str) -> Run | None:
        with self._lock:
            return self._runs.get(run_id)

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._runs.values() if r.status in ("queued", "running"))

    def recent_for_ip(self, ip: str, window_s: int = 3600) -> int:
        cutoff = time.time() - window_s
        with self._lock:
            return sum(1 for r in self._runs.values() if r.client_ip == ip and r.created >= cutoff)


store = RunStore()
