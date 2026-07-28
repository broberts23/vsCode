import uuid
from typing import Any

from app_vending.catalog import resolve_offering


def _new_role_id() -> str:
    return str(uuid.uuid4())


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
                    {"id": _permission_placeholder(permission), "type": "Role"}
                    for permission in graph_permissions
                ],
            }
        ]

    return application


def _permission_placeholder(permission_name: str) -> str:
    return f"permission-id-for-{permission_name.lower().replace('.', '-')}"


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
        "conditionalAccess": resolved.get("conditionalAccess"),
        "utcmMonitor": resolved.get("utcmMonitor"),
        "authProfile": resolved.get("authProfile"),
        "parameters": parameters,
    }
