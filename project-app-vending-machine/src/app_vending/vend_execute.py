import logging
from pathlib import Path
from typing import Any

from app_vending.catalog import get_offering, resolve_offering
from app_vending.graph_apps import execute_live_vend
from app_vending.graph_ca import build_policy_from_offering
from app_vending.settings import PROJECT_ROOT, get_execution_mode
from app_vending.utcm import render_utcm_monitor
from app_vending.vend_plan import build_vend_plan

logger = logging.getLogger(__name__)


def process_vend_request(payload: dict[str, Any], *, request_id: str) -> dict[str, Any]:
    offering_id = payload["offeringId"]
    display_name = payload["displayName"]
    owners = payload.get("owners", [])
    parameters = payload.get("parameters", {})
    justification = payload.get("justification", "")
    execution_mode = get_execution_mode()

    offering = get_offering(offering_id)
    resolved_offering = resolve_offering(offering, parameters)

    if execution_mode == "Live":
        result = execute_live_vend(
            offering,
            display_name=display_name,
            owners=owners,
            parameters=parameters,
            justification=justification,
        )
    else:
        dry_run_plan = build_vend_plan(
            offering,
            display_name=display_name,
            owners=owners,
            parameters=parameters,
            justification=justification,
        )
        ca_policy = build_policy_from_offering(
            resolved_offering,
            display_name=display_name,
            service_principal_object_id="service-principal-placeholder",
            application_id="application-client-id-placeholder",
        )
        result = {
            "applicationObjectId": "dry-run-app-object-id",
            "applicationClientId": "dry-run-client-id",
            "servicePrincipalObjectId": "dry-run-service-principal-id",
            "appRoles": dry_run_plan["application"].get("appRoles", []),
            "credential": dry_run_plan.get("credential"),
            "conditionalAccessPolicy": ca_policy,
            "dryRunPlan": dry_run_plan,
        }

    policy_display_name = (result.get("conditionalAccessPolicy") or {}).get(
        "displayName",
        f"CA - {display_name}",
    )
    utcm_result = render_utcm_monitor(
        resolved_offering,
        display_name=display_name,
        policy_display_name=policy_display_name,
        project_root=PROJECT_ROOT,
        request_id=request_id,
    )
    if utcm_result:
        result["utcmMonitorArtifact"] = utcm_result["artifactPath"]

    return {
        "status": "completed",
        "offeringId": offering_id,
        "executionMode": execution_mode,
        "result": result,
    }
