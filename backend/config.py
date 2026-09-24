from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()

MIN_TOKEN_LENGTH = 16


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str
    collector_token: str
    analyst_token: str

    def __post_init__(self) -> None:
        for name, token in [
            ("COLLECTOR_TOKEN", self.collector_token),
            ("ANALYST_TOKEN", self.analyst_token),
        ]:
            if len(token) < MIN_TOKEN_LENGTH:
                raise ConfigurationError(
                    f"{name} must be at least {MIN_TOKEN_LENGTH} characters"
                )
        if self.collector_token == self.analyst_token:
            raise ConfigurationError(
                "COLLECTOR_TOKEN and ANALYST_TOKEN must differ"
            )


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is not set; see .env.example")
    return value


def load_settings() -> Settings:
    return Settings(
        database_url=require_env("DATABASE_URL"),
        collector_token=require_env("COLLECTOR_TOKEN"),
        analyst_token=require_env("ANALYST_TOKEN"),
    )
