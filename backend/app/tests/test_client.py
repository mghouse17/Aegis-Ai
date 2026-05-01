from __future__ import annotations

import json
from unittest.mock import MagicMock

import httpx
import pytest

import app.integrations.github.client as client_module
from app.integrations.github.client import GitHubClient, RateLimitConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_response(
    status_code: int,
    headers: dict[str, str] | None = None,
    json_body: dict | None = None,
) -> httpx.Response:
    """Build a minimal httpx.Response without making any network calls."""
    content = json.dumps(json_body).encode() if json_body is not None else b""
    return httpx.Response(status_code=status_code, headers=headers or {}, content=content)


def patch_transport(gh: GitHubClient, responses: list) -> MagicMock:
    """Replace gh._client.request with a mock that yields responses/exceptions in order.

    Each entry is either an httpx.Response (returned) or an Exception subclass instance
    (raised). MagicMock's side_effect handles both cases automatically.
    """
    m = MagicMock(side_effect=responses)
    gh._client.request = m  # type: ignore[method-assign]
    return m


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sleep_log(monkeypatch) -> list[float]:
    """Patch time.sleep (no actual sleeping) and random.uniform (zero jitter).

    Both are patched on the client module's references so other stdlib code is
    unaffected. Returns a list that accumulates every duration the client would
    have slept, enabling assertions on retry timing.
    """
    calls: list[float] = []
    monkeypatch.setattr(client_module.time, "sleep", calls.append)
    monkeypatch.setattr(client_module.random, "uniform", lambda _a, _b: 0.0)
    return calls


@pytest.fixture
def gh() -> GitHubClient:
    """GitHubClient with max_retries=2 and base_delay=1.0 for predictable test math."""
    return GitHubClient(rate_limit_config=RateLimitConfig(max_retries=2, base_delay=1.0))


# ---------------------------------------------------------------------------
# 429 retries
# ---------------------------------------------------------------------------

class TestRateLimitRetries:

    def test_429_retries_and_succeeds(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [make_response(429), make_response(200)])
        resp = gh.get("/repos/foo/bar")
        assert resp.status_code == 200
        assert mock.call_count == 2
        assert len(sleep_log) == 1

    def test_429_retries_multiple_times_before_success(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            make_response(429),
            make_response(429),
            make_response(200),
        ])
        resp = gh.get("/test")
        assert resp.status_code == 200
        assert mock.call_count == 3
        assert len(sleep_log) == 2

    def test_403_ratelimit_remaining_zero_retries(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            make_response(403, headers={"x-ratelimit-remaining": "0"}),
            make_response(200),
        ])
        resp = gh.get("/test")
        assert resp.status_code == 200
        assert mock.call_count == 2
        assert len(sleep_log) == 1

    def test_403_secondary_ratelimit_message_retries(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            make_response(403, json_body={"message": "You have exceeded a secondary rate limit"}),
            make_response(200),
        ])
        resp = gh.get("/test")
        assert resp.status_code == 200
        assert mock.call_count == 2
        assert len(sleep_log) == 1

    def test_403_secondary_ratelimit_check_is_case_insensitive(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            make_response(403, json_body={"message": "API Rate Limit reached"}),
            make_response(200),
        ])
        resp = gh.get("/test")
        assert resp.status_code == 200
        assert mock.call_count == 2

    def test_plain_403_does_not_retry(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [make_response(403, json_body={"message": "Forbidden"})])
        resp = gh.get("/test")
        assert resp.status_code == 403
        assert mock.call_count == 1
        assert len(sleep_log) == 0

    def test_403_nonzero_remaining_does_not_retry(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [make_response(403, headers={"x-ratelimit-remaining": "10"})])
        resp = gh.get("/test")
        assert resp.status_code == 403
        assert mock.call_count == 1
        assert len(sleep_log) == 0

    def test_403_non_json_body_does_not_crash_or_retry(self, gh, sleep_log) -> None:
        """Non-JSON 403 body: json() raises, exception is swallowed, treated as normal 403."""
        mock = patch_transport(gh, [httpx.Response(status_code=403, content=b"not json")])
        resp = gh.get("/test")
        assert resp.status_code == 403
        assert mock.call_count == 1
        assert len(sleep_log) == 0


# ---------------------------------------------------------------------------
# Exhausted rate-limit retries
# ---------------------------------------------------------------------------

class TestExhaustedRateLimitRetries:

    def test_exhausted_429_returns_final_response(self, gh, sleep_log) -> None:
        # max_retries=2 → 3 total attempts (0, 1, 2); sleep after 0 and 1, return on 2
        mock = patch_transport(gh, [make_response(429)] * 3)
        resp = gh.get("/test")
        assert resp.status_code == 429
        assert mock.call_count == 3
        assert len(sleep_log) == 2  # slept twice, returned on the third attempt

    def test_exhausted_403_ratelimit_returns_final_response(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            make_response(403, headers={"x-ratelimit-remaining": "0"})
        ] * 3)
        resp = gh.get("/test")
        assert resp.status_code == 403
        assert mock.call_count == 3
        assert len(sleep_log) == 2

    def test_max_retries_zero_never_sleeps(self, sleep_log) -> None:
        gh0 = GitHubClient(rate_limit_config=RateLimitConfig(max_retries=0, base_delay=1.0))
        mock = patch_transport(gh0, [make_response(429)])
        resp = gh0.get("/test")
        assert resp.status_code == 429
        assert mock.call_count == 1
        assert len(sleep_log) == 0


# ---------------------------------------------------------------------------
# Network RequestError retries
# ---------------------------------------------------------------------------

class TestNetworkErrorRetries:

    def test_connect_error_retries_and_succeeds(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            httpx.ConnectError("Connection refused"),
            make_response(200),
        ])
        resp = gh.get("/test")
        assert resp.status_code == 200
        assert mock.call_count == 2
        assert len(sleep_log) == 1

    def test_read_error_retries_and_succeeds(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [
            httpx.ReadError("Connection reset"),
            make_response(200),
        ])
        resp = gh.get("/test")
        assert resp.status_code == 200
        assert mock.call_count == 2

    def test_exhausted_network_errors_raises_last_exception(self, gh, sleep_log) -> None:
        error = httpx.ConnectError("Connection refused")
        mock = patch_transport(gh, [error] * 3)
        with pytest.raises(httpx.ConnectError, match="Connection refused"):
            gh.get("/test")
        assert mock.call_count == 3
        assert len(sleep_log) == 2  # sleep after attempt 0 and 1, not after final attempt

    def test_network_error_sleep_count_equals_max_retries(self, gh, sleep_log) -> None:
        mock = patch_transport(gh, [httpx.ConnectError("err")] * 3)
        with pytest.raises(httpx.ConnectError):
            gh.get("/test")
        assert len(sleep_log) == gh._rate_config.max_retries


# ---------------------------------------------------------------------------
# Jitter/backoff is patched — delay values are deterministic
# ---------------------------------------------------------------------------

class TestDelayComputation:

    def test_rate_limit_uses_exponential_backoff_without_reset_header(
        self, gh, sleep_log
    ) -> None:
        """Without X-RateLimit-Reset, delay = base_delay * 2^attempt + jitter(=0)."""
        patch_transport(gh, [
            make_response(429),
            make_response(429),
            make_response(200),
        ])
        gh.get("/test")
        # attempt 0: 1.0 * 2^0 + 0.0 = 1.0
        # attempt 1: 1.0 * 2^1 + 0.0 = 2.0
        assert sleep_log == [1.0, 2.0]

    def test_network_error_uses_exponential_backoff(self, gh, sleep_log) -> None:
        """Network error delay = base_delay * 2^attempt + uniform(0, 0.5)(=0)."""
        patch_transport(gh, [
            httpx.ConnectError("err"),
            httpx.ConnectError("err"),
            make_response(200),
        ])
        gh.get("/test")
        # attempt 0: 1.0 * 2^0 + 0.0 = 1.0
        # attempt 1: 1.0 * 2^1 + 0.0 = 2.0
        assert sleep_log == [1.0, 2.0]

    def test_reset_header_epoch_in_future_sets_sleep_duration(
        self, gh, monkeypatch, sleep_log
    ) -> None:
        """X-RateLimit-Reset in the future → wait = (reset - now) + jitter(=0)."""
        monkeypatch.setattr(client_module.time, "time", lambda: 1000.0)
        patch_transport(gh, [
            make_response(429, headers={"x-ratelimit-reset": "1060"}),  # 60s from now
            make_response(200),
        ])
        gh.get("/test")
        assert len(sleep_log) == 1
        assert sleep_log[0] == pytest.approx(60.0)

    def test_reset_header_epoch_in_past_falls_back_to_exponential(
        self, gh, monkeypatch, sleep_log
    ) -> None:
        """Expired X-RateLimit-Reset (< now) → falls back to exponential backoff."""
        monkeypatch.setattr(client_module.time, "time", lambda: 1000.0)
        patch_transport(gh, [
            make_response(429, headers={"x-ratelimit-reset": "900"}),  # 100s ago
            make_response(200),
        ])
        gh.get("/test")
        assert sleep_log == [1.0]  # base_delay * 2^0 + jitter(0.0)

    def test_malformed_reset_header_falls_back_to_exponential(
        self, gh, sleep_log
    ) -> None:
        """Non-numeric X-RateLimit-Reset → ValueError caught → exponential fallback."""
        patch_transport(gh, [
            make_response(429, headers={"x-ratelimit-reset": "not-a-timestamp"}),
            make_response(200),
        ])
        gh.get("/test")
        assert sleep_log == [1.0]


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------

class TestContextManager:

    def test_context_manager_calls_close_on_exit(self, monkeypatch) -> None:
        gh = GitHubClient()
        close_calls: list[bool] = []
        monkeypatch.setattr(gh, "close", lambda: close_calls.append(True))
        with gh:
            pass
        assert close_calls == [True]

    def test_context_manager_calls_close_on_exception(self, monkeypatch) -> None:
        gh = GitHubClient()
        close_calls: list[bool] = []
        monkeypatch.setattr(gh, "close", lambda: close_calls.append(True))
        with pytest.raises(ValueError):
            with gh:
                raise ValueError("boom")
        assert close_calls == [True]
