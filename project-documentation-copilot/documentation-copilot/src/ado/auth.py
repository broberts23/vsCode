"""Azure DevOps authentication helpers.

Three-tier authentication strategy:

- **Production in Foundry (preferred):** Service principal client credentials flow.
  The agent's platform-assigned managed identity reads the service principal's
  client ID and client secret from Azure Key Vault, then exchanges them for a
  Microsoft Entra token via the OAuth 2.0 ``client_credentials`` grant for
  scope ``https://app.vssps.visualstudio.com/.default``. The resulting token
  is what gets sent to Azure DevOps — the ADO API recognizes the service
  principal as a valid user because it was added to the organization explicitly.
  No long-lived secret lives in the agent's environment variables.

- **Local development (fallback):** Reads ``AZURE_DEVOPS_PAT`` from the
  environment and constructs a Basic auth header. Used when running the agent
  outside of Azure (developer workstation) where no managed identity is
  available.

- **Managed identity direct (last-resort fallback):** Uses
  ``DefaultAzureCredential`` to acquire a Microsoft Entra token directly with
  the platform-assigned managed identity. This works if (and only if) the
  identity has been added as a user in Azure DevOps. In practice this fails
  with ``VS403283`` for most platform-assigned identities, so it should be
  treated as a diagnostic-only path.
"""

from __future__ import annotations

from base64 import b64encode
import logging
import os
import time

import requests

logger = logging.getLogger(__name__)


# The OAuth scope for Azure DevOps REST API access.
# When exchanging a Microsoft Entra token for Azure DevOps, this is the
# resource the token is requested for. The ``.default`` suffix means "all
# permissions the identity has been granted" (rather than a specific scope).
AD_OAUTH_SCOPE = "https://app.vssps.visualstudio.com/.default"


# Key Vault secret names (must match what Phase 1 step 5 of OUTLINE.md stores).
KV_SECRET_SP_CLIENT_ID = "AdoServicePrincipalClientId"
KV_SECRET_SP_CLIENT_SECRET = "AdoServicePrincipalSecret"
KV_SECRET_SP_OBJECT_ID = "AdoServicePrincipalObjectId"


def _key_vault_url() -> str | None:
    """Resolve the Key Vault URL from environment variables.

    Accepts either ``KEY_VAULT_NAME`` (shorthand) or ``KEY_VAULT_URL`` (full URL).
    Returns the vault URL string, or None if neither is set.
    """
    url = os.environ.get('KEY_VAULT_URL')
    if url:
        return url.rstrip('/') + '/'
    name = os.environ.get('KEY_VAULT_NAME')
    if name:
        return f'https://{name}.vault.azure.net/'
    return None


class _TokenCache:
    """Mutable container for an in-memory cached Bearer token.

    Used by both ``ServicePrincipalAuth`` and ``ManagedIdentityAuth`` to
    share the refresh-on-expiry pattern.
    """

    __slots__ = ('token', 'expires_at')

    def __init__(self) -> None:
        self.token: str | None = None
        self.expires_at: float = 0.0

    def is_valid(self, skew_seconds: float = 60.0) -> bool:
        if self.token is None:
            return False
        return time.time() < self.expires_at - skew_seconds


class ServicePrincipalAuth(requests.auth.AuthBase):
    """Per-request Microsoft Entra token acquisition via the service principal.

    Production auth path. The agent's platform-assigned managed identity reads
    the service principal's client ID and client secret from Key Vault, then
    exchanges them for a Microsoft Entra token via the OAuth 2.0
    ``client_credentials`` grant. Tokens are cached in-memory and refreshed
    60 seconds before expiry.

    Implements the ``requests.auth.AuthBase`` protocol so the
    ``requests.Session`` invokes ``__call__`` on every outbound request.
    """

    def __init__(self, scope: str = AD_OAUTH_SCOPE) -> None:
        self.scope = scope
        self._cache = _TokenCache()
        self._kv_credential: object | None = None
        self._secret_client: object | None = None
        self._tenant_id: str | None = None
        self._client_id: str | None = None
        self._client_secret: str | None = None

    def _ensure_secret_client(self):
        if self._secret_client is not None:
            return self._secret_client
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        vault_url = _key_vault_url()
        if not vault_url:
            raise RuntimeError(
                'ServicePrincipalAuth requires KEY_VAULT_NAME or KEY_VAULT_URL '
                'environment variable pointing to the vault that holds the '
                'AdoServicePrincipal* secrets.'
            )
        logger.info('ServicePrincipalAuth: using Key Vault %s', vault_url)
        self._kv_credential = DefaultAzureCredential()
        self._secret_client = SecretClient(
            vault_url=vault_url, credential=self._kv_credential)
        return self._secret_client

    def _load_credentials(self) -> None:
        if self._client_id and self._client_secret and self._tenant_id:
            return
        secret_client = self._ensure_secret_client()
        try:
            self._client_id = secret_client.get_secret(
                KV_SECRET_SP_CLIENT_ID).value
            self._client_secret = secret_client.get_secret(
                KV_SECRET_SP_CLIENT_SECRET).value
        except Exception as exc:
            vault_url = _key_vault_url() or '<unknown>'
            raise RuntimeError(
                f'Failed to load service principal secrets from Key Vault '
                f'{vault_url}. Required secrets: {KV_SECRET_SP_CLIENT_ID!r}, '
                f'{KV_SECRET_SP_CLIENT_SECRET!r}. '
                f'Store them via: '
                f'az keyvault secret set --vault-name <vault> '
                f'--name {KV_SECRET_SP_CLIENT_ID} --value <app_id> ; '
                f'az keyvault secret set --vault-name <vault> '
                f'--name {KV_SECRET_SP_CLIENT_SECRET} --value <client_secret> '
                f'Underlying error: {exc}'
            ) from exc
        # The object ID isn't needed for token acquisition but is logged
        # for diagnostics.
        try:
            _ = secret_client.get_secret(KV_SECRET_SP_OBJECT_ID).value
        except Exception:
            pass  # optional
        # Tenant ID is required for the token endpoint.
        self._tenant_id = os.environ.get('AZURE_TENANT_ID')
        if not self._tenant_id:
            raise RuntimeError(
                'AZURE_TENANT_ID environment variable is required for the '
                'service principal auth flow (the OAuth 2.0 token endpoint '
                'is tenant-specific).'
            )

    def _refresh(self) -> None:
        self._load_credentials()
        token_url = (
            f'https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token'
        )
        response = requests.post(
            token_url,
            data={
                'client_id': self._client_id,
                'scope': self.scope,
                'client_secret': self._client_secret,
                'grant_type': 'client_credentials',
            },
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f'Service principal token exchange failed: '
                f'{response.status_code} {response.text[:500]}'
            )
        data = response.json()
        self._cache.token = data['access_token']
        self._cache.expires_at = time.time() + int(data.get('expires_in', 3600))
        logger.debug(
            'Refreshed ADO Bearer token via service principal, expires in %ss',
            data.get('expires_in'),
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if not self._cache.is_valid():
            self._refresh()
        request.headers['Authorization'] = f'Bearer {self._cache.token}'
        return request


class ManagedIdentityAuth(requests.auth.AuthBase):
    """Per-request Microsoft Entra token acquisition via managed identity.

    Last-resort auth path. ``DefaultAzureCredential`` resolves to the
    platform-assigned managed identity in the Foundry container. Tokens are
    cached in-memory and refreshed 60 seconds before expiry.
    """

    def __init__(self, scope: str = AD_OAUTH_SCOPE) -> None:
        self.scope = scope
        self._cache = _TokenCache()
        self._credential: object | None = None

    def _ensure_credential(self):
        if self._credential is None:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        return self._credential

    def _refresh(self) -> None:
        credential = self._ensure_credential()
        token = credential.get_token(self.scope)
        self._cache.token = token.token
        self._cache.expires_at = token.expires_on
        logger.debug(
            'Refreshed ADO Bearer token via managed identity, expires at %s',
            self._cache.expires_at,
        )

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        if not self._cache.is_valid():
            self._refresh()
        request.headers['Authorization'] = f'Bearer {self._cache.token}'
        return request


def _try_service_principal_token(scope: str) -> str | None:
    """Attempt to acquire a Bearer token via the service principal flow.

    Returns the token, or None if the service principal is not configured
    (no Key Vault, missing secrets, missing tenant ID) or the token exchange
    fails. Failures are logged at INFO level (not DEBUG) so they surface in
    the agent's operational logs — a silent fall-through to managed identity
    is a real auth failure, not a diagnostic curiosity.
    """
    try:
        auth = ServicePrincipalAuth(scope=scope)
        # Force a token fetch now to surface any errors at construction time.
        auth._refresh()
        return auth._cache.token
    except Exception as exc:
        logger.warning(
            'Service principal token acquisition failed (will fall back to '
            'managed identity): %s', exc,
        )
        return None


def _try_managed_identity_token(scope: str) -> str | None:
    """Attempt to acquire a Bearer token directly via managed identity."""
    try:
        auth = ManagedIdentityAuth(scope=scope)
        auth._refresh()
        return auth._cache.token
    except Exception as exc:
        logger.debug('Managed identity token acquisition failed: %s', exc)
        return None


def get_bearer_token(scope: str = AD_OAUTH_SCOPE) -> str | None:
    """Try to acquire a Microsoft Entra Bearer token for the ADO scope.

    Returns the token, or None if no credential path is available.

    Priority:
        1. Service principal via Key Vault (production in Foundry)
        2. Platform-assigned managed identity direct
        3. None
    """
    token = _try_service_principal_token(scope)
    if token:
        logger.info('Acquired ADO token via service principal (Key Vault)')
        return token

    token = _try_managed_identity_token(scope)
    if token:
        logger.info('Acquired ADO token via managed identity direct')
        return token

    return None


def _service_principal_configured() -> bool:
    """Return True if a service principal can be loaded from Key Vault.

    Used by AdoWikiClient to choose between the SP and managed-identity
    AuthBase handlers at session construction time.
    """
    if not _key_vault_url():
        return False
    if not os.environ.get('AZURE_TENANT_ID'):
        return False
    return True


def build_session_auth() -> tuple[requests.auth.AuthBase, str]:
    """Construct the right ``AuthBase`` handler for the runtime environment.

    Returns a ``(handler, description)`` tuple. The description is for logging.

    Priority:
        1. ``ServicePrincipalAuth`` when Key Vault URL and tenant ID are set
        2. ``ManagedIdentityAuth`` as fallback
    """
    if _service_principal_configured():
        try:
            return ServicePrincipalAuth(), 'service principal (Key Vault)'
        except Exception as exc:
            logger.warning('Service principal init failed, falling back to managed identity: %s', exc)
    return ManagedIdentityAuth(), 'managed identity direct'


def get_auth_header() -> dict[str, str]:
    """Build the Authorization header for Azure DevOps REST API calls.

    Static version of the auth flow — used as a one-shot helper, not for
    per-request use. For long-running sessions, use ``build_session_auth()``
    to get an ``AuthBase`` handler that refreshes the token on each call.
    """
    token = get_bearer_token()
    if token:
        return {'Authorization': f'Bearer {token}'}

    pat = os.environ.get('AZURE_DEVOPS_PAT', '')
    if not pat:
        raise RuntimeError(
            'Azure DevOps authentication failed. Ensure either: '
            '(1) KEY_VAULT_NAME (or KEY_VAULT_URL) and AZURE_TENANT_ID are set '
            'so the agent can read the service principal secret from Key Vault, '
            'or (2) AZURE_DEVOPS_PAT is set for local development. '
            'Generate a PAT at https://dev.azure.com/{org}/_usersSettings/tokens '
            'with the Wiki Read & Write scope.'
        )
    encoded = b64encode(f':{pat}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': f'Basic {encoded}'}
