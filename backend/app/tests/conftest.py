from __future__ import annotations

import hashlib
import hmac
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=False)
def mock_webhook_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    """Inject GITHUB_WEBHOOK_SECRET. Returns the secret so tests can compute signatures."""
    secret = "test-webhook-secret-for-pytest"
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", secret)
    return secret


def make_signature(body: bytes, secret: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def make_pr_payload(
    action: str = "opened",
    pr_number: int = 42,
    installation_id: int | None = 99999,
) -> dict:
    payload: dict = {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "id": 1001,
            "number": pr_number,
            "title": "Add feature X",
            "state": "open",
            "body": "Adds feature X.",
            "head": {"sha": "abc123", "ref": "feature-x"},
            "base": {"sha": "def456", "ref": "main"},
        },
        "repository": {
            "id": 555,
            "name": "my-repo",
            "full_name": "org/my-repo",
            "private": True,
        },
        "sender": {"id": 111, "login": "octocat"},
    }
    if installation_id is not None:
        payload["installation"] = {"id": installation_id}
    return payload


@pytest.fixture
def client() -> TestClient:
    return TestClient(app, raise_server_exceptions=True)
