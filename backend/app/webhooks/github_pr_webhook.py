from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.integrations.github.idempotency import DeliveryTracker, NoOpDeliveryTracker
from app.integrations.github.types import PullRequestEvent
from app.integrations.github.webhook import verify_signature

logger = logging.getLogger(__name__)
router = APIRouter()

MAX_BODY_SIZE = 25 * 1024 * 1024  # 25 MB — GitHub's documented webhook payload limit
_HANDLED_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


def get_delivery_tracker() -> DeliveryTracker:
    """FastAPI dependency. Override at app startup to inject a Redis/DB implementation."""
    return NoOpDeliveryTracker()


@router.post("/webhooks/github/pr")
async def github_pr_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    delivery_tracker: DeliveryTracker = Depends(get_delivery_tracker),
) -> dict[str, Any]:
    logger.info(
        "webhook_received",
        extra={"event_type": x_github_event, "delivery_id": x_github_delivery},
    )

    # 1. Guard against abnormally large payloads before any processing.
    body: bytes = await request.body()
    if len(body) > MAX_BODY_SIZE:
        raise HTTPException(status_code=413, detail="Payload too large")

    # 2. Verify signature on the exact bytes GitHub signed.
    verify_signature(body, x_hub_signature_256)

    # 3. Filter by event type — cheapest check after signature.
    if x_github_event != "pull_request":
        logger.info(
            "webhook_ignored",
            extra={"reason": "non_pr_event", "event_type": x_github_event},
        )
        return {"status": "ignored"}

    # 4. Parse from the verified raw bytes.
    try:
        payload: dict[str, Any] = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}") from exc

    # 5. Filter by action before full Pydantic validation.
    action = payload.get("action", "")
    if action not in _HANDLED_ACTIONS:
        logger.info(
            "webhook_ignored",
            extra={"reason": "unhandled_action", "action": action},
        )
        return {"status": "ignored"}

    # 6. Idempotency check — return early if this delivery was already accepted.
    if x_github_delivery and delivery_tracker.is_duplicate(x_github_delivery):
        logger.info("webhook_duplicate", extra={"delivery_id": x_github_delivery})
        return {"status": "accepted"}  # idempotent — already processed

    # 7. Validate and normalise payload into typed model.
    try:
        event = PullRequestEvent.from_webhook(payload, delivery_id=x_github_delivery)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Payload validation failed: {exc}") from exc

    # 8. Mark delivery as seen before enqueuing (prevents duplicates on retry).
    if x_github_delivery:
        delivery_tracker.mark_seen(x_github_delivery)

    logger.info(
        "webhook_accepted",
        extra={
            "action": event.action,
            "pr_number": event.number,
            "repo_id": event.repository.id,  # ID not name — consistent volume at scale
            "delivery_id": event.delivery_id,
        },
    )

    # TODO: enqueue event for processing (queue layer — not implemented here)
    return {"status": "accepted"}
