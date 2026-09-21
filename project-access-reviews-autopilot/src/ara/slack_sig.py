"""Slack request signature verification (HMAC-SHA256)."""

from __future__ import annotations

import hashlib
import hmac
import time


class SlackSignatureError(ValueError):
    pass


def verify_slack_signature(
    *,
    signing_secret: str,
    timestamp: str,
    body: bytes | str,
    signature: str,
    max_age_seconds: int = 60 * 5,
) -> None:
    if not signing_secret:
        raise SlackSignatureError("Slack signing secret is not configured")
    if not timestamp or not signature:
        raise SlackSignatureError("Missing Slack signature headers")

    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise SlackSignatureError("Invalid Slack timestamp") from exc

    if abs(int(time.time()) - ts) > max_age_seconds:
        raise SlackSignatureError("Slack request timestamp is too old")

    body_text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else body
    basestring = f"v0:{timestamp}:{body_text}".encode("utf-8")
    digest = hmac.new(
        signing_secret.encode("utf-8"),
        basestring,
        hashlib.sha256,
    ).hexdigest()
    expected = f"v0={digest}"
    if not hmac.compare_digest(expected, signature):
        raise SlackSignatureError("Slack signature mismatch")
