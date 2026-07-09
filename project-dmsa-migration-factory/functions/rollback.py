import logging

import azure.functions as func

from contracts.migration import rollback_request_from_dict
from domains.migration import rollback_service
from domains.validation import validate_service
from shared.config import load_config, validate_config
from shared.logging import configure_logging
from shared.powershell import PowerShellError, ScriptTimeoutError, WinRMPowerShellRunner, require_success, to_json

bp = func.Blueprint()


@bp.route(route="rollback", methods=["POST"])
def rollback(req: func.HttpRequest) -> func.HttpResponse:
    configure_logging()
    try:
        request = rollback_request_from_dict(req.get_json())
        config = load_config()
        validate_config(config)

        # If this was a superseding migration, undo the AD migration on the DC
        if request.domain_controller and request.dmsa_name and request.superseded_account:
            dc_runner = WinRMPowerShellRunner(
                request.domain_controller, config, request.domain_controller_thumbprint)
            undo_result = dc_runner.run_script("Undo-DMSA.ps1", {
                "Identity": request.dmsa_name,
                "SupersededAccount": request.superseded_account,
            })
            require_success(undo_result)
            logging.info("Undo-DMSA migration undone on DC for %s", request.dmsa_name)

        # Roll back the member server: clear DelegatedMSAEnabled, reconfigure service
        member_runner = WinRMPowerShellRunner(
            request.target_host, config, request.target_host_thumbprint)
        rollback_result = rollback_service(member_runner, request)
        validation_result = validate_service(member_runner, request.service_name, request.previous_account)
        return func.HttpResponse(
            to_json({"rollback": rollback_result, "validation": validation_result}),
            mimetype="application/json",
        )
    except (ValueError, PowerShellError) as exc:
        logging.exception("rollback failed")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=400, mimetype="application/json")
    except ScriptTimeoutError as exc:
        logging.exception("rollback timed out")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=504, mimetype="application/json")