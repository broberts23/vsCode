"""HTTP Function that fetches host facts from the App Proxy published on-prem API."""

from __future__ import annotations

import json
import logging
import os

import azure.functions as func
import httpx
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

DEFAULT_BASE_URL = "https://projectfastapi-benrobertsio.msappproxy.net"
DEFAULT_SCOPE = "https://projectfastapi-benrobertsio.msappproxy.net/.default"
HOST_PATH = "/api/host"
# App Proxy Entra pre-auth consumes Authorization; backend reads this copy.
ON_PREM_ACCESS_TOKEN_HEADER = "X-OnPrem-Access-Token"


def _settings() -> tuple[str, str]:
    base_url = os.environ.get("ON_PREM_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    scope = os.environ.get("ON_PREM_API_SCOPE", DEFAULT_SCOPE)
    return base_url, scope


def _access_token(scope: str) -> str:
    credential = DefaultAzureCredential(
        exclude_interactive_browser_credential=True,
    )
    return credential.get_token(scope).token


@app.route(route="onprem-host", methods=["GET"])
def onprem_host(req: func.HttpRequest) -> func.HttpResponse:
    """Return JSON from the on-prem `/api/host` endpoint via App Proxy."""
    del req  # trigger binding required; no query inputs for this step
    base_url, scope = _settings()
    target = f"{base_url}{HOST_PATH}"
    logging.info("Fetching on-prem host facts from %s", target)

    try:
        token = _access_token(scope)
    except ClientAuthenticationError as exc:
        logging.exception("Failed to acquire Entra access token for scope %s", scope)
        return func.HttpResponse(
            body=json.dumps(
                {
                    "error": "token_acquisition_failed",
                    "scope": scope,
                    "detail": (
                        "Could not get a token via DefaultAzureCredential. "
                        "Confirm Application ID URI + exposed scope match ON_PREM_API_SCOPE, "
                        "Azure CLI is an authorized client, and `az login` is for this tenant."
                    ),
                    "reason": str(exc),
                }
            ),
            status_code=401,
            mimetype="application/json",
        )

    try:
        response = httpx.get(
            target,
            headers={
                "Authorization": f"Bearer {token}",
                ON_PREM_ACCESS_TOKEN_HEADER: token,
            },
            timeout=30.0,
            follow_redirects=True,
        )
    except httpx.HTTPError:
        logging.exception("HTTP call to on-prem API failed: %s", target)
        return func.HttpResponse(
            body=json.dumps(
                {
                    "error": "upstream_unreachable",
                    "detail": f"Request to {target} failed.",
                }
            ),
            status_code=502,
            mimetype="application/json",
        )

    content_type = response.headers.get("content-type", "application/json")
    return func.HttpResponse(
        body=response.content,
        status_code=response.status_code,
        mimetype=content_type.split(";")[0].strip() or "application/json",
    )
