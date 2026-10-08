"""Runtime settings, read from environment variables at call time (easy to override in tests)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    @property
    def anthropic_api_key(self) -> str | None:
        return os.getenv("ANTHROPIC_API_KEY") or None

    @property
    def model_choices(self) -> list[str]:
        """Models a caller may pick for a run (allow-list; set MODEL_CHOICES to a comma-separated list to change it)."""
        raw = os.getenv("MODEL_CHOICES", "claude-sonnet-5-5,claude-opus-5-5,claude-haiku-4-5-20251001,claude-fable-5-1")
        return [m.strip() for m in raw.split(",") if m.strip()]

    @property
    def model_orchestrator(self) -> str:
        return os.getenv("MODEL_ORCHESTRATOR", os.getenv("MODEL_CONVERTER", "claude-sonnet-5-5"))

    @property
    def model_critic(self) -> str:
        return os.getenv("MODEL_CRITIC", os.getenv("MODEL_CONVERTER", "claude-sonnet-5-5"))

    @property
    def model_converter(self) -> str:
        return os.getenv("MODEL_CONVERTER", "claude-sonnet-5-5")

    @property
    def model_reviewer(self) -> str:
        return os.getenv("MODEL_REVIEWER", os.getenv("MODEL_CONVERTER", "claude-sonnet-5-5"))

    @property
    def database_url(self) -> str | None:
        url = os.getenv("DATABASE_URL") or None
        # Render and Heroku style URLs
        if url and url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        return url

    @property
    def access_code(self) -> str | None:
        """If set, runs that can spend LLM budget require this code."""
        return os.getenv("ACCESS_CODE") or None

    @property
    def max_upload_bytes(self) -> int:
        return int(float(os.getenv("MAX_UPLOAD_MB", "5")) * 1024 * 1024)

    @property
    def max_files(self) -> int:
        return int(os.getenv("MAX_FILES", "600"))

    @property
    def max_statements(self) -> int:
        return int(os.getenv("MAX_STATEMENTS", "250"))

    @property
    def llm_concurrency(self) -> int:
        return int(os.getenv("LLM_CONCURRENCY", "4"))

    @property
    def max_repair_attempts(self) -> int:
        return int(os.getenv("MAX_REPAIR_ATTEMPTS", "2"))

    @property
    def max_concurrent_runs(self) -> int:
        return int(os.getenv("MAX_CONCURRENT_RUNS", "2"))

    @property
    def runs_per_hour_per_ip(self) -> int:
        return int(os.getenv("RUNS_PER_HOUR_PER_IP", "20"))

    @property
    def data_dir(self) -> Path:
        d = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data")))
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def sample_app_dir(self) -> Path:
        return BASE_DIR / "sample_apps" / "acme-orders-oracle"


settings = Settings()
