import json
import os
import logging

import azure.functions as func
from datetime import datetime, timedelta, timezone
from services.arc_orchestrator import ArcOrchestrator
from clients.table import get_table_service_client, get_table_client

logging.basicConfig(level=logging.INFO)
orchestrator = ArcOrchestrator()
table_service_client = get_table_service_client()
table_client = get_table_client()

bp = func.Blueprint()


@bp.route(route="jit/elevate", methods=["POST"])
def jit_elevate_access(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing JIT elevation request.")

    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "BAD_REQUEST",
                       "details": "Invalid JSON payload format."}),
            status_code=400,
            mimetype="application/json"
        )
    dmsa_name = req_body.get('dmsa_name')
    target_group = req_body.get('target_group')
    if not dmsa_name or not target_group:
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "MISSING_FIELDS",
                       "details": "dmsa_name and target_group are mandatory fields."}),
            status_code=400,
            mimetype="application/json"
        )
    try:
        execution_id = orchestrator.execute_ad_change(
            dmsa_name, target_group, "elevate")
        response_data = {
            "status": "success",
            "message": f"Elevation request for {dmsa_name} to {target_group} has been processed.",
            "execution_id": execution_id
        }
        return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")
    except Exception as e:
        logging.error(f"Failed to execute Azure Arc deployment task: {str(e)}")
        return func.HttpResponse(
            json.dumps(
                {"status": "error", "error_code": "EXECUTION_FAILURE", "details": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
    # Record State inside Azure Table Storage with a 60-minute lifetime expiration
    try:
        expiration_time = datetime.now(timezone.utc) + timedelta(minutes=60)
        table_service_client.create_entity(
            entity={
                "PartitionKey": "JitActiveList",
                "RowKey": f"{dmsa_name}_{target_group}",
                "DmsaName": dmsa_name,
                "TargetGroup": target_group,
                "Action": "elevate",
                "Timestamp": datetime.now(timezone.utc).isoformat(),
                "ExpirationTime": expiration_time.isoformat()
            }
        )
        return func.HttpResponse(
            json.dumps({
                "status": "success",
                "message": f"Elevation request for {dmsa_name} to {target_group} has been logged.",
                "expiration_time": expiration_time.isoformat()
            }),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(
            f"Failed to log JIT elevation request in Table Storage: {str(e)}")
