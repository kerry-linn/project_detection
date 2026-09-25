from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

MIN_TOKEN_LENGTH = 16
DEFAULT_SESSION_LIFETIME = timedelta(hours=8)


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str
    collector_token: str
    session_lifetime: timedelta = DEFAULT_SESSION_LIFETIME

    def __post_init__(self) -> None:
        if len(self.collector_token) < MIN_TOKEN_LENGTH:
            raise ConfigurationError(
                f"COLLECTOR_TOKEN must be at least {MIN_TOKEN_LENGTH} characters"
            )
        if self.session_lifetime <= timedelta(0):
            raise ConfigurationError("SESSION_LIFETIME_MINUTES must be positive")


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"{name} is not set; see .env.example")
    return value


def load_settings() -> Settings:
    lifetime_minutes = os.environ.get("SESSION_LIFETIME_MINUTES", "").strip()
    session_lifetime = DEFAULT_SESSION_LIFETIME
    if lifetime_minutes:
        try:
            session_lifetime = timedelta(minutes=int(lifetime_minutes))
        except ValueError as error:
            raise ConfigurationError(
                "SESSION_LIFETIME_MINUTES must be an integer"
            ) from error
    return Settings(
        database_url=require_env("DATABASE_URL"),
        collector_token=require_env("COLLECTOR_TOKEN"),
        session_lifetime=session_lifetime,
    )
