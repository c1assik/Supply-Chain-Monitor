"""Application settings, read from the environment and `.env`."""

from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCM_", env_file=".env", extra="ignore")

    # Secrets have no defaults: without them the service refuses to start.
    database_url: SecretStr
    redis_url: SecretStr
    scoring_config_path: Path = Path("config/scoring.yaml")

    s3_endpoint: str = "http://localhost:8333"
    s3_access_key: SecretStr
    s3_secret_key: SecretStr
    s3_bucket: str = "artifacts"

    telegram_token: SecretStr | None = None
    telegram_chat_id: str | None = None

    feed_poll_interval_s: float = 45
    catchup_interval_s: float = 300
    # Files of one release are uploaded one by one, so give the upload a moment to finish.
    release_settle_s: float = 60
    sweep_stale_after_s: float = 900
    max_tries: int = 5
    retry_delay_s: float = 30
    worker_max_jobs: int = 8
    analyzer_processes: int = 4
    analyzer_timeout_s: float = 120

    top_packages_url: str = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
    top_packages_limit: int = 5000

    max_artifact_bytes: int = 100 * 1024 * 1024
    max_unpacked_bytes: int = 512 * 1024 * 1024
    max_unpacked_files: int = 20_000
    max_compression_ratio: int = 200

    metrics_port: int = 9100


@lru_cache
def get_settings() -> Settings:
    return Settings()
