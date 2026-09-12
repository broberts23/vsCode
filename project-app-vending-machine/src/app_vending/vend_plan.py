import uuid
from typing import Any
from uuid import UUID

from app_vending.catalog import resolve_offering
from app_vending.graph_ca import build_policy_from_offering

# Well-known Microsoft Graph application permission role IDs.
# Source: https://learn.microsoft.com/graph/permissions-reference
GRAPH_APPLICATION_PERMISSION_IDS = {
    "User.Read.All": "df021247-61c5-41a9-9423-5e42018f874e",
    "Directory.Read.All": "7ab1d382-f21e-4cad-ac8a-35da30492d92",
    "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44acfd2f",
    "Group.Read.All": "5b567255-7703-4780-807c-7be8301ae99b",
    "Mail.Read": "810c84a8-4a9e-49e6-bf7d-b6d169e3ef5d",
}


def _new_role_id() -> str:
    return str(uuid.uuid4())


def resolve_graph_permission_id(permission_name: str) -> str:
    known = GRAPH_APPLICATION_PERMISSION_IDS.get(permission_name)
    if known:
        return known
    # Deterministic fallback keeps Live Graph payloads valid GUID shapes
    # even when an uncommon permission is added to the catalog later.
    return str(UUID(uuid.uuid5(uuid.NAMESPACE_URL, f"graph-app-permission:{permission_name}")))


def build_app_registration_plan(
    offering: dict[str, Any],
    display_name: str,
    owners: list[str],
) -> dict[str, Any]:
    auth_profile = offering.get("authProfile", {})
    platform = auth_profile.get("platform", "web")
    redirect_uris = auth_profile.get("redirectUris", [])

    app_roles = []
    for role in offering.get("appRoles", []):
        app_roles.append(
            {
                "id": _new_role_id(),
                "displayName": role["displayName"],
                "value": role["value"],
                "allowedMemberTypes": role.get("allowedMemberTypes", ["User"]),
                "description": role.get("description", role["displayName"]),
                "isEnabled": True,
            }
        )

    application = {
        "displayName": display_name,
        "signInAudience": "AzureADMyOrg",
        "owners": owners,
        "appRoles": app_roles,
    }

    token_version = auth_profile.get("requestedAccessTokenVersion")
    cae = auth_profile.get("cae") or {}
    if cae.get("enabled") and token_version is None:
        token_version = 2
    if token_version is not None:
        application["api"] = {"requestedAccessTokenVersion": token_version}

    if cae.get("enabled"):
        application["optionalClaims"] = {
            "accessToken": [
                {
                    "name": "xms_cc",
                    "essential": False,
                    "source": None,
                }
            ],
            "idToken": [],
            "saml2Token": [],
        }

    if platform == "spa":
        application["spa"] = {"redirectUris": redirect_uris}
    else:
        application["web"] = {
            "redirectUris": redirect_uris,
            "implicitGrantSettings": {"enableIdTokenIssuance": False},
        }

    federated = auth_profile.get("federatedCredential")
    if federated:
        application["federatedCredential"] = federated

    graph_permissions = offering.get("graphApplicationPermissions", [])
    if graph_permissions:
        application["requiredResourceAccess"] = [
            {
                "resourceAppId": "00000003-0000-0000-c000-000000000000",
                "resourceAccess": [
                    {"id": resolve_graph_permission_id(permission), "type": "Role"}
                    for permission in graph_permissions
                ],
            }
        ]

    return application


def build_service_principal_plan(application_object_id: str, display_name: str) -> dict[str, Any]:
    return {
        "appId": application_object_id,
        "displayName": display_name,
        "accountEnabled": True,
        "tags": ["HideApp", "WindowsAzureActiveDirectoryIntegratedApp"],
    }


def build_credential_plan(offering: dict[str, Any]) -> dict[str, Any] | None:
    strategy = offering.get("credentialStrategy", "none")
    if strategy == "none":
        return None
    if strategy == "secret":
        return {
            "displayName": "vended-client-secret",
            "endDateTime": "P180D",
        }
    if strategy == "certificate":
        return {
            "displayName": "vended-workload-certificate",
            "usage": "Verify",
            "type": "AsymmetricX509Cert",
        }
    raise ValueError(f"Unsupported credential strategy '{strategy}'.")


def build_vend_plan(
    offering: dict[str, Any],
    *,
    display_name: str,
    owners: list[str],
    parameters: dict[str, Any],
    justification: str,
) -> dict[str, Any]:
    resolved = resolve_offering(offering, parameters)
    app_plan = build_app_registration_plan(resolved, display_name, owners)
    credential_plan = build_credential_plan(resolved)
    ca_policy = build_policy_from_offering(
        resolved,
        display_name=display_name,
        application_id="application-client-id-placeholder",
        service_principal_object_id="service-principal-placeholder",
    )

    return {
        "justification": justification,
        "offeringId": resolved["offeringId"],
        "displayName": display_name,
        "application": app_plan,
        "servicePrincipal": {
            "displayName": display_name,
            "dependsOn": "application",
        },
        "credential": credential_plan,
        "conditionalAccess": ca_policy or resolved.get("conditionalAccess"),
        "utcmMonitor": resolved.get("utcmMonitor"),
        "authProfile": resolved.get("authProfile"),
        "parameters": parameters,
    }
