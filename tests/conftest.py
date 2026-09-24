from __future__ import annotations

import os

import psycopg
import pytest

import backend.config  # noqa: F401  loads .env so TEST_DATABASE_URL is available
from backend.db import apply_migrations, connect


@pytest.fixture(scope="session")
def migrated_database_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is not set; see .env.example")
    try:
        with connect(url) as conn:
            if not conn.info.dbname.endswith("_test"):
                pytest.fail("TEST_DATABASE_URL must name a database ending in _test")
            apply_migrations(conn)
    except psycopg.OperationalError as error:
        pytest.skip(f"test database unavailable ({error}); run docker compose up")
    return url


@pytest.fixture
def database_url(migrated_database_url: str) -> str:
    with connect(migrated_database_url) as conn:
        conn.execute(
            "TRUNCATE alert_events, alerts, detection_runs, security_events "
            "RESTART IDENTITY"
        )
    return migrated_database_url
