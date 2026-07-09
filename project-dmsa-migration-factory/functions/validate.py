import logging

import azure.functions as func

from domains.validation import validate_service
from shared.config import load_config, validate_config
from shared.logging import configure_logging
from shared.powershell import PowerShellError, ScriptTimeoutError, WinRMPowerShellRunner, to_json

bp = func.Blueprint()


@bp.route(route="validate", methods=["POST"])
def validate(req: func.HttpRequest) -> func.HttpResponse:
    configure_logging()
    try:
        body = req.get_json()
        service_name = body.get("serviceName")
        if not service_name:
            raise ValueError("Missing required field: serviceName")
        target_host = body.get("targetHost")
        if not target_host:
            raise ValueError("Missing required field: targetHost")
        config = load_config()
        validate_config(config)
        result = validate_service(
            WinRMPowerShellRunner(target_host, config, body.get("targetHostThumbprint")),
            str(service_name),
            body.get("expectedAccount"),
        )
        return func.HttpResponse(to_json(result), mimetype="application/json")
    except (ValueError, PowerShellError) as exc:
        logging.exception("validation failed")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=400, mimetype="application/json")
    except ScriptTimeoutError as exc:
        logging.exception("validation timed out")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=504, mimetype="application/json")