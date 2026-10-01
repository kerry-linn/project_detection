from __future__ import annotations

import os
from typing import Callable

import psycopg
import pytest
from fastapi.testclient import TestClient

import backend.config  # noqa: F401  loads .env so TEST_DATABASE_URL is available
from backend.api import create_app
from backend.auth import hash_password
from backend.config import Settings
from backend.db import apply_migrations, connect
from scripts.seed import seed_lab

TEST_PASSWORD = "lab-password-for-tests"
COLLECTOR_TOKEN = "collector-token-for-tests"
CLIENT_IP = "203.0.113.10"

LoginAs = Callable[[str], dict[str, str]]


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
            "TRUNCATE alert_replacements, alert_events, alerts, detection_runs, security_events, "
            "sessions, documents, users, organizations RESTART IDENTITY"
        )
    return migrated_database_url


@pytest.fixture(scope="session")
def seed_password_hash() -> str:
    return hash_password(TEST_PASSWORD)


@pytest.fixture
def settings(database_url: str) -> Settings:
    return Settings(database_url=database_url, collector_token=COLLECTOR_TOKEN)


@pytest.fixture
def client(
    database_url: str, settings: Settings, seed_password_hash: str
) -> TestClient:
    with connect(database_url) as conn:
        seed_lab(conn, seed_password_hash)
    return TestClient(create_app(settings), client=(CLIENT_IP, 50000))


@pytest.fixture
def login_as(client: TestClient) -> LoginAs:
    def login(account: str) -> dict[str, str]:
        response = client.post(
            "/auth/login", json={"login": account, "password": TEST_PASSWORD}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return login
