import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def send_callback(
    callback_url: str,
    payload: dict[str, Any],
    *,
    callback_secret: str | None = None,
) -> bool:
    headers = {"Content-Type": "application/json"}
    body = json.dumps(payload)

    if callback_secret:
        signature = hmac.new(
            callback_secret.encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        headers["X-AppVending-Signature"] = signature

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.post(callback_url, content=body, headers=headers)
            response.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.warning("Callback to %s failed: %s", callback_url, exc)
        return False
