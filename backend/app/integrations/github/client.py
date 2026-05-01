from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    max_retries: int = 3
    base_delay: float = 1.0


class GitHubClient:
    """Synchronous httpx wrapper with rate-limit detection, jitter, and exponential backoff."""

    def __init__(
        self,
        base_url: str = "https://api.github.com",
        token: str | None = None,
        rate_limit_config: RateLimitConfig | None = None,
    ) -> None:
        self._rate_config = rate_limit_config or RateLimitConfig()
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, timeout=30.0
        )

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self._request("POST", path, **kwargs)

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self._rate_config.max_retries + 1):
            try:
                response = self._client.request(method, path, **kwargs)

                if self._is_rate_limited(response):
                    if attempt < self._rate_config.max_retries:
                        delay = self._compute_delay(
                            attempt, response.headers.get("X-RateLimit-Reset")
                        )
                        logger.warning(
                            "github_rate_limited",
                            extra={"attempt": attempt, "retry_after_seconds": delay},
                        )
                        time.sleep(delay)
                        continue
                    return response  # exhausted retries — return rate-limit response to caller

                # Non-rate-limit 4xx/5xx: return immediately, do not retry
                return response

            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < self._rate_config.max_retries:
                    delay = self._rate_config.base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                    logger.warning(
                        "github_request_error",
                        extra={"attempt": attempt, "error": str(exc)},
                    )
                    time.sleep(delay)

        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Request failed after all retries")  # pragma: no cover

    def _is_rate_limited(self, response: httpx.Response) -> bool:
        if response.status_code == 429:
            return True
        if response.status_code == 403:
            remaining = response.headers.get("X-RateLimit-Remaining")
            if remaining is not None and int(remaining) == 0:
                return True
            # GitHub secondary rate limits: 403 with rate limit message in body
            try:
                if "rate limit" in response.json().get("message", "").lower():
                    return True
            except Exception:
                pass
        return False

    def _compute_delay(self, attempt: int, reset_at: str | None) -> float:
        """Delay = reset window (or exponential backoff) + uniform jitter."""
        jitter = random.uniform(0, self._rate_config.base_delay)
        if reset_at is not None:
            try:
                wait = float(reset_at) - time.time()
                if 0 < wait < 3600:
                    return wait + jitter
            except ValueError:
                pass
        return self._rate_config.base_delay * (2 ** attempt) + jitter

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
