#!/usr/bin/env python3
"""Obtain a Bearer token using OAuth 2.0 authorization code + PKCE."""

import argparse
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import msal

DEFAULT_SCOPE = "api://{client_id}/.default"
REDIRECT_URI = "http://localhost:8400/callback"


class CallbackHandler(BaseHTTPRequestHandler):
    auth_code: str | None = None

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        CallbackHandler.auth_code = query.get("code", [None])[0]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Authentication complete. You can close this window.")

    def log_message(self, format, *args):
        return


def get_token(tenant_id: str, client_id: str, scope: str) -> str:
    app = msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    flow = app.initiate_auth_code_flow(
        scopes=[scope],
        redirect_uri=REDIRECT_URI,
    )
    webbrowser.open(flow["auth_uri"])

    server = HTTPServer(("localhost", 8400), CallbackHandler)
    server.handle_request()

    if not CallbackHandler.auth_code:
        raise RuntimeError("Authorization code was not returned.")

    result = app.acquire_token_by_auth_code_flow(flow, {"code": CallbackHandler.auth_code})
    if "access_token" not in result:
        raise RuntimeError(json.dumps(result, indent=2))
    return result["access_token"]


def main():
    parser = argparse.ArgumentParser(description="Get a PKCE Bearer token for the vending API.")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--scope", default=None)
    args = parser.parse_args()

    scope = args.scope or DEFAULT_SCOPE.format(client_id=args.client_id)
    token = get_token(args.tenant_id, args.client_id, scope)
    print(token)


if __name__ == "__main__":
    main()
