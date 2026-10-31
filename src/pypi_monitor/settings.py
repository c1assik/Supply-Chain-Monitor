"""Application settings, read from the environment and `.env`."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCM_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://scm:scm@localhost:5432/scm"
    scoring_config_path: Path = Path("config/scoring.yaml")


@lru_cache
def get_settings() -> Settings:
    return Settings()
