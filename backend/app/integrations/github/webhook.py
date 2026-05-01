from __future__ import annotations

import hashlib
import hmac
import logging
import os

from fastapi import HTTPException

logger = logging.getLogger(__name__)


def verify_signature(body: bytes, signature_header: str | None) -> None:
    """Verify X-Hub-Signature-256 against raw request body.

    Raises HTTPException(401) on any verification failure.
    Raises HTTPException(500) if the webhook secret is not configured.
    Never logs body content or the secret value.
    """
    if not signature_header or not signature_header.strip():
        logger.warning("webhook_signature_missing")
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header")

    if not signature_header.startswith("sha256="):
        logger.warning("webhook_signature_malformed")
        raise HTTPException(status_code=401, detail="Malformed X-Hub-Signature-256 header")

    received_mac = signature_header.removeprefix("sha256=")
    if not received_mac:
        logger.warning("webhook_signature_empty_value")
        raise HTTPException(status_code=401, detail="Empty signature value")

    try:
        secret = os.environ["GITHUB_WEBHOOK_SECRET"]
    except KeyError:
        logger.error("webhook_secret_not_configured")
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    if not secret:
        logger.error("webhook_secret_empty")
        raise HTTPException(status_code=500, detail="Webhook secret is empty")

    expected_mac = hmac.new(
        secret.encode("utf-8"), msg=body, digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(received_mac, expected_mac):
        logger.warning("webhook_signature_invalid")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
