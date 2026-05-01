from __future__ import annotations

import logging
import os
import time

import jwt

logger = logging.getLogger(__name__)


def generate_app_jwt() -> str:
    """Generate a GitHub App JWT valid for 60 seconds.

    Reads GITHUB_APP_ID and GITHUB_PRIVATE_KEY from the environment at call time.
    """
    app_id: str = os.environ["GITHUB_APP_ID"]
    # Private key may use literal \n in env files — normalise to real newlines
    private_key = os.environ["GITHUB_PRIVATE_KEY"].replace("\\n", "\n")
    now = int(time.time())
    payload = {
        "iat": now - 60,  # 60s back for clock-skew tolerance
        "exp": now + 60,  # GitHub max is 10 minutes; 60s is sufficient for short-lived ops
        "iss": app_id,
    }
    token = jwt.encode(payload, private_key, algorithm="RS256")
    logger.debug("github_app_jwt_generated", extra={"app_id": app_id})
    return token
