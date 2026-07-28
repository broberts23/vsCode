from typing import Any


def build_user_compliant_device_policy(display_name: str, *, report_only: bool = True) -> dict[str, Any]:
    state = "enabledForReportingButNotEnforced" if report_only else "enabled"
    return {
        "displayName": f"CA - {display_name} - Compliant Device",
        "state": state,
        "conditions": {
            "applications": {
                "includeApplications": ["All"],
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


def build_policy_from_offering(
    offering: dict[str, Any],
    *,
    display_name: str,
    service_principal_object_id: str | None = None,
) -> dict[str, Any] | None:
    ca_config = offering.get("conditionalAccess")
    if not ca_config:
        return None

    template = ca_config.get("template")
    report_only = ca_config.get("mode", "reportOnly") != "enabled"
    parameters = ca_config.get("parameters", {})

    if template == "require-compliant-device":
        return build_user_compliant_device_policy(display_name, report_only=report_only)

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
