from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.tests.conftest import make_pr_payload, make_signature

pytestmark = pytest.mark.usefixtures("mock_webhook_secret")


class TestPRWebhookEndpoint:

    def _post_pr(
        self,
        client: TestClient,
        payload: dict,
        secret: str,
        action: str = "pull_request",
        delivery_id: str = "delivery-001",
    ):
        body = json.dumps(payload).encode()
        return client.post(
            "/webhooks/github/pr",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": make_signature(body, secret),
                "X-GitHub-Event": action,
                "X-GitHub-Delivery": delivery_id,
            },
        )

    def test_opened_returns_accepted(self, client: TestClient, mock_webhook_secret: str) -> None:
        resp = self._post_pr(client, make_pr_payload(action="opened"), mock_webhook_secret)
        assert resp.status_code == 200
        assert resp.json() == {"status": "accepted"}

    def test_synchronize_returns_accepted(self, client: TestClient, mock_webhook_secret: str) -> None:
        resp = self._post_pr(client, make_pr_payload(action="synchronize"), mock_webhook_secret)
        assert resp.status_code == 200
        assert resp.json() == {"status": "accepted"}

    def test_reopened_returns_accepted(self, client: TestClient, mock_webhook_secret: str) -> None:
        resp = self._post_pr(client, make_pr_payload(action="reopened"), mock_webhook_secret)
        assert resp.status_code == 200
        assert resp.json() == {"status": "accepted"}

    def test_closed_action_returns_ignored(self, client: TestClient, mock_webhook_secret: str) -> None:
        resp = self._post_pr(client, make_pr_payload(action="closed"), mock_webhook_secret)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored"}

    def test_edited_action_returns_ignored(self, client: TestClient, mock_webhook_secret: str) -> None:
        resp = self._post_pr(client, make_pr_payload(action="edited"), mock_webhook_secret)
        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored"}

    def test_push_event_returns_ignored(self, client: TestClient, mock_webhook_secret: str) -> None:
        body = json.dumps({"ref": "refs/heads/main"}).encode()
        resp = client.post(
            "/webhooks/github/pr",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": make_signature(body, mock_webhook_secret),
                "X-GitHub-Event": "push",
            },
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored"}

    def test_issues_event_returns_ignored(self, client: TestClient, mock_webhook_secret: str) -> None:
        body = json.dumps({"action": "opened"}).encode()
        resp = client.post(
            "/webhooks/github/pr",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": make_signature(body, mock_webhook_secret),
                "X-GitHub-Event": "issues",
            },
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ignored"}

    def test_missing_signature_returns_401(self, client: TestClient) -> None:
        body = json.dumps(make_pr_payload()).encode()
        resp = client.post(
            "/webhooks/github/pr",
            content=body,
            headers={"Content-Type": "application/json", "X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 401

    def test_wrong_signature_returns_401(self, client: TestClient) -> None:
        body = json.dumps(make_pr_payload()).encode()
        resp = client.post(
            "/webhooks/github/pr",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=" + "b" * 64,
                "X-GitHub-Event": "pull_request",
            },
        )
        assert resp.status_code == 401

    def test_malformed_json_returns_400(self, client: TestClient, mock_webhook_secret: str) -> None:
        body = b"not valid json {"
        resp = client.post(
            "/webhooks/github/pr",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": make_signature(body, mock_webhook_secret),
                "X-GitHub-Event": "pull_request",
            },
        )
        assert resp.status_code == 400

    def test_missing_required_field_returns_400(self, client: TestClient, mock_webhook_secret: str) -> None:
        payload = make_pr_payload(action="opened")
        del payload["repository"]
        resp = self._post_pr(client, payload, mock_webhook_secret)
        assert resp.status_code == 400

    def test_oversized_body_returns_413(self, client: TestClient, mock_webhook_secret: str) -> None:
        body = b"x" * (25 * 1024 * 1024 + 1)
        resp = client.post(
            "/webhooks/github/pr",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": make_signature(body, mock_webhook_secret),
                "X-GitHub-Event": "pull_request",
            },
        )
        assert resp.status_code == 413

    def test_health_endpoint(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
