"""Test fixtures.

The suite runs entirely on a throwaway SQLite database and never touches the network:
the analysis orchestrator is replaced with a deterministic fake in API tests, and the
analyzer/fetcher tests operate on in-memory inputs. This is what lets `pytest` verify the
whole system with zero external services.
"""

from __future__ import annotations

import os
import tempfile

import pytest

# Configure a fully isolated environment BEFORE importing the app.
_TMP_DB = os.path.join(tempfile.gettempdir(), "warden_test.db")
os.environ.update(
    ENV="development",
    DEBUG="false",
    DATABASE_URL=f"sqlite+pysqlite:///{_TMP_DB}",
    REDIS_OPTIONAL="true",
    REDIS_URL="redis://localhost:6390/0",  # intentionally unused -> in-process fallback
    SECRET_KEY="test-secret-key-that-is-sufficiently-long-1234567890",
    FIRST_ADMIN_EMAIL="admin@warden.io",
    FIRST_ADMIN_PASSWORD="AdminPassw0rd!2026",
    RATE_LIMIT_PER_MINUTE="100000",
    AUTH_RATE_LIMIT_PER_MINUTE="100000",
)

if os.path.exists(_TMP_DB):
    os.remove(_TMP_DB)

from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.session import engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_token(client) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@warden.io", "password": "AdminPassw0rd!2026"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
