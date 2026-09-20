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
    sif = dict(session_controls.get("signInFrequency") or {})
    cae = dict(session_controls.get("continuousAccessEvaluation") or {})
    requested_cae_mode = cae.get("mode") if cae else None
    # Graph 1138: strictEnforcement is rolled back / rejected. Keep supported modes only.
    # App-level CAE (xms_cc / cp1) still applies without this session control.
    unsupported_cae = {"strictEnforcement"}
    include_cae = bool(requested_cae_mode) and requested_cae_mode not in unsupported_cae

    # Graph 1085: Continuous Access Evaluation cannot be set in report-only mode.
    # When a supported CAE session control is present, the policy must be enabled.
    effective_report_only = report_only and not include_cae
    state = "enabledForReportingButNotEnforced" if effective_report_only else "enabled"

    sign_in_frequency = {
        "isEnabled": sif.get("isEnabled", True),
        "type": sif.get("type", "hours"),
        "value": sif.get("value", 1),
        "frequencyInterval": sif.get("frequencyInterval", "timeBased"),
    }

    session: dict[str, Any] = {
        "signInFrequency": sign_in_frequency,
    }
    if include_cae:
        session["continuousAccessEvaluation"] = {
            "mode": requested_cae_mode,
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
        "sessionControls": session,
    }


def build_ip_named_location_body(
    display_name: str,
    *,
    allowed_ip_ranges: list[str],
) -> dict[str, Any]:
    """Graph ipNamedLocation body (CIDR allow-list for workload CA)."""
    ip_ranges: list[dict[str, str]] = []
    for cidr in allowed_ip_ranges:
        value = str(cidr).strip()
        if not value:
            continue
        # Heuristic: treat IPv6 CIDRs as iPv6CidrRange; everything else as IPv4.
        odata_type = (
            "#microsoft.graph.iPv6CidrRange"
            if ":" in value
            else "#microsoft.graph.iPv4CidrRange"
        )
        ip_ranges.append({"@odata.type": odata_type, "cidrAddress": value})

    return {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": f"NL - {display_name} - Allowed IPs",
        "isTrusted": True,
        "ipRanges": ip_ranges,
    }


def build_workload_ip_restrict_policy(
    display_name: str,
    *,
    service_principal_ids: list[str],
    named_location_id: str,
    report_only: bool = True,
) -> dict[str, Any]:
    """Workload-identity CA: block SP token requests outside an IP named location.

    Matches Microsoft's workload identity CA Graph sample (beta):
    applications=All, clientApplications.includeServicePrincipals, locations
    include All / exclude named location, grant=block.
    """
    state = "enabledForReportingButNotEnforced" if report_only else "enabled"
    return {
        "displayName": f"CA - {display_name} - Workload IP Restriction",
        "state": state,
        "conditions": {
            "applications": {
                "includeApplications": ["All"],
            },
            "clientApplications": {
                "includeServicePrincipals": service_principal_ids,
                "excludeServicePrincipals": [],
            },
            "locations": {
                "includeLocations": ["All"],
                "excludeLocations": [named_location_id],
            },
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
    if "continuousAccessEvaluation" in session:
        return True
    conditions = policy_body.get("conditions") or {}
    # Workload-identity CA (clientApplications) is documented on the beta endpoint.
    return "clientApplications" in conditions


def build_policy_from_offering(
    offering: dict[str, Any],
    *,
    display_name: str,
    service_principal_object_id: str | None = None,
    application_id: str | None = None,
    named_location_id: str | None = None,
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
            allowed_ip_ranges = [part.strip() for part in allowed_ip_ranges.split(",") if part.strip()]

        location_id = named_location_id or "named-location-placeholder"
        policy = build_workload_ip_restrict_policy(
            display_name,
            service_principal_ids=[service_principal_object_id or "service-principal-placeholder"],
            named_location_id=location_id,
            report_only=report_only,
        )
        # Attach dry-run / staging metadata for named location creation (stripped before Graph POST).
        policy["_namedLocation"] = build_ip_named_location_body(
            display_name,
            allowed_ip_ranges=allowed_ip_ranges,
        )
        return policy

    raise ValueError(f"Unsupported conditional access template '{template}'.")
