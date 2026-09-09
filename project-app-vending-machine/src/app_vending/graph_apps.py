import logging
from typing import Any

import httpx
from azure.identity import DefaultAzureCredential

from app_vending.graph_ca import build_policy_from_offering
from app_vending.settings import get_graph_tenant_id
from app_vending.vend_plan import build_vend_plan

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
BETA_GRAPH_BASE = "https://graph.microsoft.com/beta"

logger = logging.getLogger(__name__)


def get_graph_token() -> str:
    tenant_id = get_graph_tenant_id()
    if not tenant_id:
        raise ValueError("GRAPH_TENANT_ID is required for Live mode.")
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


def create_application(token: str, application_body: dict[str, Any]) -> dict[str, Any]:
    owners = application_body.pop("owners", [])
    federated = application_body.pop("federatedCredential", None)
    created = _graph_request("POST", f"{GRAPH_BASE}/applications", token=token, json_body=application_body)

    for owner_id in owners:
        try:
            _graph_request(
                "POST",
                f"{GRAPH_BASE}/applications/{created['id']}/owners/$ref",
                token=token,
                json_body={"@odata.id": f"{GRAPH_BASE}/directoryObjects/{owner_id}"},
            )
        except RuntimeError as exc:
            logger.warning(
                "Skipping owner assignment for %s on application %s: %s",
                owner_id,
                created.get("id"),
                exc,
            )

    if federated:
        _graph_request(
            "POST",
            f"{BETA_GRAPH_BASE}/applications/{created['id']}/federatedIdentityCredentials",
            token=token,
            json_body={
                "name": "aks-workload-identity",
                "issuer": federated["issuer"],
                "subject": federated["subject"],
                "audiences": ["api://AzureADTokenExchange"],
            },
        )

    return created


def create_service_principal(token: str, app_id: str, display_name: str) -> dict[str, Any]:
    return _graph_request(
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


def create_conditional_access_policy(token: str, policy_body: dict[str, Any]) -> dict[str, Any]:
    return _graph_request(
        "POST",
        f"{GRAPH_BASE}/identity/conditionalAccess/policies",
        token=token,
        json_body=policy_body,
    )


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

    ca_policy_plan = build_policy_from_offering(
        offering,
        display_name=display_name,
        service_principal_object_id=service_principal["id"],
    )
    ca_policy = None
    if ca_policy_plan:
        ca_policy = create_conditional_access_policy(token, ca_policy_plan)

    return {
        "applicationObjectId": application["id"],
        "applicationClientId": application["appId"],
        "servicePrincipalObjectId": service_principal["id"],
        "appRoles": application.get("appRoles", []),
        "credential": credential_result,
        "conditionalAccessPolicy": ca_policy or ca_policy_plan,
        "dryRunPlan": None,
    }
