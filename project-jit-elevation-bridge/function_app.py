import azure.functions as func
import json
import logging
from services.arc_orchestrator import ArcOrchestrator

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


@app.route(route="jit/modify", methods=["POST"])
def jit_modify_access(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing JIT Active Directory group adjustment request.")

    # 1. Parse Input Data Structure
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
    action = req_body.get('action')

    # 2. Keep Input Validations Simple and Literal
    if not all([dmsa_name, target_group, action]):
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "MISSING_FIELDS",
                       "details": "dmsa_name, target_group, and action are mandatory fields."}),
            status_code=400,
            mimetype="application/json"
        )

    if action not in ["elevate", "revoke"]:
        return func.HttpResponse(
            json.dumps({"status": "error", "error_code": "INVALID_ACTION",
                       "details": "Action must be strictly 'elevate' or 'revoke'."}),
            status_code=400,
            mimetype="application/json"
        )

    # 3. Direct Execution Logic without Excessive Layering
    try:
        orchestrator = ArcOrchestrator()
        execution_id = orchestrator.execute_ad_change(
            dmsa_name, target_group, action)

        response_data = {
            "status": "success",
            "message": f"Action '{action}' successfully executed for {dmsa_name}.",
            "execution_id": execution_id
        }
        return func.HttpResponse(json.dumps(response_data), status_code=200, mimetype="application/json")

    except Exception as e:
        # Catch unexpected infrastructure issues cleanly without losing context
        logging.error(f"Failed to execute Azure Arc deployment task: {str(e)}")
        return func.HttpResponse(
            json.dumps(
                {"status": "error", "error_code": "EXECUTION_FAILURE", "details": str(e)}),
            status_code=500,
            mimetype="application/json"
        )
