import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEST_DSN = os.getenv("TEST_DATABASE_URL", "postgresql://postgres@127.0.0.1:54329/postgres")


def _pg_reachable(dsn: str) -> bool:
    try:
        import psycopg
        with psycopg.connect(dsn, connect_timeout=3):
            return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def pg_dsn():
    if not _pg_reachable(TEST_DSN):
        pytest.skip("no PostgreSQL available (set TEST_DATABASE_URL)")
    return TEST_DSN


@pytest.fixture()
def sandbox(pg_dsn):
    from app.flows.oracle_pg.sandbox import Sandbox
    sb = Sandbox(pg_dsn, uuid.uuid4().hex)
    sb.setup()
    assert sb.live, sb.error
    yield sb
    sb.teardown()


@pytest.fixture()
def sample_root():
    from app.config import settings
    return settings.sample_app_dir


class FakeLLM:
    """Stands in for Claude so the agent plumbing (escalation, repair loop, guards) can be tested offline.
    `answers` maps a substring of the user prompt to the tool input to return."""

    def __init__(self, answers=None, review=None):
        self.answers = answers or {}
        self.review = review or []
        self.calls = []
        self.usage = {}
        self.last_error = None
        self.disabled = False

    available = True

    def call_tool(self, *, agent, model, system, user, tool_name, tool_description, schema, max_tokens=0):
        self.calls.append((agent, tool_name, user))
        if tool_name == "submit_review":
            return {"risks": self.review}
        if tool_name == "submit_summary":
            return {"summary": "fake summary"}
        for needle, ans in self.answers.items():
            if needle in user:
                if callable(ans):
                    return ans(user)
                return ans
        return None

    def usage_summary(self):
        return {"calls": len(self.calls), "input_tokens": 0, "output_tokens": 0, "by_agent": {}}
