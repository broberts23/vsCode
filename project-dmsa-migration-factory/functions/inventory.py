import logging

import azure.functions as func

from domains.inventory import discover_services
from shared.config import load_config, validate_config
from shared.logging import configure_logging
from shared.powershell import PowerShellError, ScriptTimeoutError, WinRMPowerShellRunner, to_json

bp = func.Blueprint()


@bp.route(route="inventory", methods=["GET"])
def inventory(req: func.HttpRequest) -> func.HttpResponse:
    configure_logging()
    try:
        host = req.params.get("host") or "localhost"
        config = load_config()
        validate_config(config)
        result = discover_services(WinRMPowerShellRunner(host, config), host)
        return func.HttpResponse(to_json(result), mimetype="application/json")
    except (ValueError, PowerShellError) as exc:
        logging.exception("inventory failed")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=400, mimetype="application/json")
    except ScriptTimeoutError as exc:
        logging.exception("inventory timed out")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=504, mimetype="application/json")