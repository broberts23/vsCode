import logging
import os
import time
from typing import Any

import httpx
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential

from app_vending.catalog import resolve_offering
from app_vending.graph_ca import build_policy_from_offering, policy_requires_beta
from app_vending.settings import get_graph_tenant_id, get_worker_client_id
from app_vending.vend_plan import build_vend_plan

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
BETA_GRAPH_BASE = "https://graph.microsoft.com/beta"

logger = logging.getLogger(__name__)


def get_graph_token() -> str:
    tenant_id = get_graph_tenant_id()
    if not tenant_id:
        raise ValueError("GRAPH_TENANT_ID is required for Live mode.")
    # Prefer the user-assigned worker identity for Graph; do not use AZURE_CLIENT_ID
    # globally so system-assigned MI remains the storage / Azure RBAC identity.
    worker_client_id = get_worker_client_id()
    if worker_client_id:
        credential = ManagedIdentityCredential(client_id=worker_client_id)
    else:
        credential = DefaultAzureCredential()
    token = credential.get_token(GRAPH_SCOPE)
    return token.token


def _graph_request(
    method: str,
    url: str,
    *,
    token: str,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    with httpx.Client(timeout=30.0) as client:
        response = client.request(method, url, headers=headers, json=json_body)
        if response.status_code >= 400:
            raise RuntimeError(f"Graph request failed ({response.status_code}): {response.text}")
        if response.content:
            return response.json()
        return {}


def resolve_caller_principal_id(token: str) -> str:
    """Object ID of the worker managed identity (required for Application.ReadWrite.OwnedBy)."""
    explicit = os.environ.get("WORKER_PRINCIPAL_ID", "").strip()
    if explicit:
        return explicit
    client_id = get_worker_client_id()
    if not client_id:
        raise RuntimeError("WORKER_CLIENT_ID or WORKER_PRINCIPAL_ID is required for Live ownership.")
    data = _graph_request(
        "GET",
        f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{client_id}'&$select=id",
        token=token,
    )
    values = data.get("value") or []
    if not values:
        raise RuntimeError(f"No service principal found for managed identity appId {client_id}")
    return values[0]["id"]


def _wait_for_application(token: str, application_object_id: str, *, attempts: int = 10) -> None:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            _graph_request(
                "GET",
                f"{GRAPH_BASE}/applications/{application_object_id}?$select=id",
                token=token,
            )
            return
        except RuntimeError as exc:
            last_error = exc
            time.sleep(min(0.5 * (2**attempt), 8))
    raise RuntimeError(f"Application {application_object_id} not readable after create: {last_error}")


def _add_owner_with_retry(
    token: str,
    application_object_id: str,
    owner_id: str,
    *,
    attempts: int = 10,
) -> None:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            _graph_request(
                "POST",
                f"{GRAPH_BASE}/applications/{application_object_id}/owners/$ref",
                token=token,
                json_body={"@odata.id": f"{GRAPH_BASE}/directoryObjects/{owner_id}"},
            )
            return
        except RuntimeError as exc:
            # Already an owner is success for our purposes.
            if "already exists" in str(exc).lower() or "one or more added object references" in str(exc).lower():
                return
            last_error = exc
            time.sleep(min(0.5 * (2**attempt), 8))
    raise RuntimeError(
        f"Failed to add owner {owner_id} on application {application_object_id}: {last_error}"
    )


def _create_federated_credential_with_retry(
    token: str,
    application_object_id: str,
    federated: dict[str, Any],
    *,
    attempts: int = 10,
) -> dict[str, Any]:
    last_error: Exception | None = None
    body = {
        "name": "aks-workload-identity",
        "issuer": federated["issuer"],
        "subject": federated["subject"],
        "audiences": ["api://AzureADTokenExchange"],
    }
    for attempt in range(attempts):
        try:
            return _graph_request(
                "POST",
                f"{BETA_GRAPH_BASE}/applications/{application_object_id}/federatedIdentityCredentials",
                token=token,
                json_body=body,
            )
        except RuntimeError as exc:
            last_error = exc
            # App object can briefly 404 on beta FIC right after create/ownership.
            if "404" in str(exc) or "Request_ResourceNotFound" in str(exc):
                time.sleep(min(0.5 * (2**attempt), 8))
                continue
            raise
    raise RuntimeError(
        f"Failed to create federated credential on application {application_object_id}: {last_error}"
    )


def create_application(token: str, application_body: dict[str, Any]) -> dict[str, Any]:
    owners = application_body.pop("owners", [])
    federated = application_body.pop("federatedCredential", None)
    created = _graph_request("POST", f"{GRAPH_BASE}/applications", token=token, json_body=application_body)
    app_object_id = created["id"]

    # Application.ReadWrite.OwnedBy can only manage apps the caller owns.
    # Claim ownership (with replication retries) before SP/secret/CA work.
    _wait_for_application(token, app_object_id)
    worker_principal_id = resolve_caller_principal_id(token)
    _add_owner_with_retry(token, app_object_id, worker_principal_id)

    for owner_id in owners:
        if owner_id == worker_principal_id:
            continue
        try:
            _add_owner_with_retry(token, app_object_id, owner_id)
        except RuntimeError as exc:
            logger.warning(
                "Skipping owner assignment for %s on application %s: %s",
                owner_id,
                app_object_id,
                exc,
            )

    if federated:
        _create_federated_credential_with_retry(token, app_object_id, federated)

    return created


def create_service_principal(token: str, app_id: str, display_name: str) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(8):
        try:
            created = _graph_request(
                "POST",
                f"{GRAPH_BASE}/servicePrincipals",
                token=token,
                json_body={
                    "appId": app_id,
                    "displayName": display_name,
                    "accountEnabled": True,
                    "tags": ["HideApp", "WindowsAzureActiveDirectoryIntegratedApp"],
                },
            )
            _wait_for_service_principal(token, app_id)
            return created
        except RuntimeError as exc:
            last_error = exc
            # OwnedBy replication can lag briefly after ownership is granted.
            if "403" in str(exc) or "Authorization_RequestDenied" in str(exc):
                time.sleep(min(0.5 * (2**attempt), 8))
                continue
            raise
    raise RuntimeError(f"Failed to create service principal for appId {app_id}: {last_error}")


def _wait_for_service_principal(token: str, app_id: str, *, attempts: int = 12) -> dict[str, Any]:
    """CA includeApplications resolves appId → SP; Graph 1034 if SP not replicated yet."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            data = _graph_request(
                "GET",
                f"{GRAPH_BASE}/servicePrincipals?$filter=appId eq '{app_id}'&$select=id,appId",
                token=token,
            )
            values = data.get("value") or []
            if values:
                return values[0]
        except RuntimeError as exc:
            last_error = exc
        time.sleep(min(0.5 * (2**attempt), 8))
    raise RuntimeError(
        f"Service principal for appId {app_id} not readable after create: {last_error}"
    )


def create_client_secret(token: str, application_object_id: str, display_name: str) -> dict[str, Any]:
    return _graph_request(
        "POST",
        f"{GRAPH_BASE}/applications/{application_object_id}/addPassword",
        token=token,
        json_body={
            "passwordCredential": {
                "displayName": display_name,
            }
        },
    )


def create_ip_named_location(token: str, named_location_body: dict[str, Any]) -> dict[str, Any]:
    created = _graph_request(
        "POST",
        f"{GRAPH_BASE}/identity/conditionalAccess/namedLocations",
        token=token,
        json_body=named_location_body,
    )
    location_id = created["id"]
    _wait_for_named_location(token, location_id)
    return created


def _wait_for_named_location(token: str, named_location_id: str, *, attempts: int = 12) -> None:
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            _graph_request(
                "GET",
                f"{GRAPH_BASE}/identity/conditionalAccess/namedLocations/{named_location_id}",
                token=token,
            )
            return
        except RuntimeError as exc:
            last_error = exc
            time.sleep(min(0.5 * (2**attempt), 8))
    raise RuntimeError(f"Named location {named_location_id} not readable after create: {last_error}")


def create_conditional_access_policy(
    token: str,
    policy_body: dict[str, Any],
    *,
    use_beta: bool = False,
    attempts: int = 8,
) -> dict[str, Any]:
    body = {key: value for key, value in policy_body.items() if not key.startswith("_")}
    base = BETA_GRAPH_BASE if use_beta else GRAPH_BASE

    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            return _graph_request(
                "POST",
                f"{base}/identity/conditionalAccess/policies",
                token=token,
                json_body=body,
            )
        except RuntimeError as exc:
            last_error = exc
            error_text = str(exc)
            # Named location can lag directory replication after create (Graph 1040).
            # App/SP can lag for CA includeApplications (Graph 1034 ServicePrincipalNotFound).
            if (
                "1040" in error_text
                or ("NamedLocation" in error_text and "does not exist" in error_text)
                or "1034" in error_text
                or "ServicePrincipalNotFound" in error_text
            ):
                time.sleep(min(0.5 * (2**attempt), 8))
                continue
            raise
    raise RuntimeError(f"Failed to create Conditional Access policy after retries: {last_error}")


def execute_live_vend(
    offering: dict[str, Any],
    *,
    display_name: str,
    owners: list[str],
    parameters: dict[str, Any],
    justification: str,
) -> dict[str, Any]:
    plan = build_vend_plan(
        offering,
        display_name=display_name,
        owners=owners,
        parameters=parameters,
        justification=justification,
    )
    resolved = resolve_offering(offering, parameters)
    token = get_graph_token()

    application = create_application(token, dict(plan["application"]))
    service_principal = create_service_principal(token, application["appId"], display_name)

    credential_result = None
    credential_plan = plan.get("credential")
    if credential_plan and offering.get("credentialStrategy") == "secret":
        credential_result = create_client_secret(
            token,
            application["id"],
            credential_plan["displayName"],
        )
    elif credential_plan and offering.get("credentialStrategy") == "certificate":
        credential_result = {
            "strategy": "certificate",
            "status": "planned",
            "message": "Upload or generate a certificate and register it on the application; federated credentials are preferred for AKS.",
            "displayName": credential_plan.get("displayName"),
        }

    named_location_id = None
    ca_draft = build_policy_from_offering(
        resolved,
        display_name=display_name,
        service_principal_object_id=service_principal["id"],
        application_id=application["appId"],
    )
    named_location_body = (ca_draft or {}).pop("_namedLocation", None) if ca_draft else None
    if named_location_body:
        created_location = create_ip_named_location(token, named_location_body)
        named_location_id = created_location["id"]

    ca_policy_plan = build_policy_from_offering(
        resolved,
        display_name=display_name,
        service_principal_object_id=service_principal["id"],
        application_id=application["appId"],
        named_location_id=named_location_id,
    )
    if ca_policy_plan:
        ca_policy_plan.pop("_namedLocation", None)

    ca_policy = None
    if ca_policy_plan:
        try:
            ca_policy = create_conditional_access_policy(
                token,
                ca_policy_plan,
                use_beta=policy_requires_beta(ca_policy_plan),
            )
            if named_location_id:
                ca_policy = {**ca_policy, "namedLocationId": named_location_id}
        except RuntimeError as exc:
            error_text = str(exc)
            # Workload-identity CA requires Entra Workload ID Premium (Graph 1149).
            if "1149" in error_text or "workload identity premium" in error_text.lower():
                logger.warning(
                    "Skipping workload Conditional Access policy (license required): %s",
                    exc,
                )
                ca_policy = {
                    **ca_policy_plan,
                    "status": "skipped",
                    "skipReason": (
                        "Tenant is not licensed for Conditional Access for workload identities "
                        "(Microsoft Entra Workload ID Premium). Named location was created; "
                        "policy body is returned as planned only."
                    ),
                    "namedLocationId": named_location_id,
                }
            else:
                raise

    return {
        "applicationObjectId": application["id"],
        "applicationClientId": application["appId"],
        "servicePrincipalObjectId": service_principal["id"],
        "appRoles": application.get("appRoles", []),
        "credential": credential_result,
        "conditionalAccessPolicy": ca_policy or ca_policy_plan,
        "dryRunPlan": None,
    }
