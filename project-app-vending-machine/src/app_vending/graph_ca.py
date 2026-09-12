from typing import Any


def build_user_compliant_device_policy(
    display_name: str,
    *,
    report_only: bool = True,
    application_id: str | None = None,
) -> dict[str, Any]:
    state = "enabledForReportingButNotEnforced" if report_only else "enabled"
    include_applications = [application_id] if application_id else ["All"]
    return {
        "displayName": f"CA - {display_name} - Compliant Device",
        "state": state,
        "conditions": {
            "applications": {
                "includeApplications": include_applications,
            },
            "users": {
                "includeUsers": ["All"],
            },
            "platforms": {
                "includePlatforms": ["all"],
            },
        },
        "grantControls": {
            "operator": "AND",
            "builtInControls": ["compliantDevice"],
        },
    }


def build_privileged_session_policy(
    display_name: str,
    *,
    application_id: str,
    session_controls: dict[str, Any],
    report_only: bool = True,
) -> dict[str, Any]:
    state = "enabledForReportingButNotEnforced" if report_only else "enabled"
    sif = dict(session_controls.get("signInFrequency") or {})
    cae = dict(session_controls.get("continuousAccessEvaluation") or {})

    sign_in_frequency = {
        "isEnabled": sif.get("isEnabled", True),
        "type": sif.get("type", "hours"),
        "value": sif.get("value", 1),
        "frequencyInterval": sif.get("frequencyInterval", "timeBased"),
    }

    return {
        "displayName": f"CA - {display_name} - Privileged Session",
        "state": state,
        "conditions": {
            "applications": {
                "includeApplications": [application_id],
            },
            "users": {
                "includeUsers": ["All"],
            },
            "clientAppTypes": ["all"],
        },
        "grantControls": {
            "operator": "AND",
            "builtInControls": ["compliantDevice"],
        },
        "sessionControls": {
            "signInFrequency": sign_in_frequency,
            "continuousAccessEvaluation": {
                "mode": cae.get("mode", "strictEnforcement"),
            },
        },
    }


def build_workload_ip_restrict_policy(
    display_name: str,
    *,
    service_principal_ids: list[str],
    allowed_ip_ranges: list[str],
    report_only: bool = True,
) -> dict[str, Any]:
    state = "enabledForReportingButNotEnforced" if report_only else "enabled"
    return {
        "displayName": f"CA - {display_name} - Workload IP Restriction",
        "state": state,
        "conditions": {
            "applications": {
                "includeServicePrincipals": service_principal_ids,
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": [],
            },
            "ipRanges": allowed_ip_ranges,
        },
        "grantControls": {
            "operator": "AND",
            "builtInControls": ["block"],
        },
    }


def policy_requires_beta(policy_body: dict[str, Any] | None) -> bool:
    if not policy_body:
        return False
    session = policy_body.get("sessionControls") or {}
    return "continuousAccessEvaluation" in session


def build_policy_from_offering(
    offering: dict[str, Any],
    *,
    display_name: str,
    service_principal_object_id: str | None = None,
    application_id: str | None = None,
) -> dict[str, Any] | None:
    ca_config = offering.get("conditionalAccess")
    if not ca_config:
        return None

    template = ca_config.get("template")
    report_only = ca_config.get("mode", "reportOnly") != "enabled"
    parameters = ca_config.get("parameters", {})

    if template == "require-compliant-device":
        return build_user_compliant_device_policy(display_name, report_only=report_only)

    if template == "require-compliant-device-privileged-session":
        return build_privileged_session_policy(
            display_name,
            application_id=application_id or "application-client-id-placeholder",
            session_controls=ca_config.get("sessionControls") or {},
            report_only=report_only,
        )

    if template == "workload-ip-location-restrict":
        allowed_ip_ranges = parameters.get("allowedIpRanges", [])
        if isinstance(allowed_ip_ranges, str):
            allowed_ip_ranges = [allowed_ip_ranges]
        return build_workload_ip_restrict_policy(
            display_name,
            service_principal_ids=[service_principal_object_id or "service-principal-placeholder"],
            allowed_ip_ranges=allowed_ip_ranges,
            report_only=report_only,
        )

    raise ValueError(f"Unsupported conditional access template '{template}'.")
