import logging
import time

import azure.functions as func

from contracts.migration import migration_request_from_dict
from domains.migration import create_dmsa, migrate_service
from domains.validation import validate_service
from shared.config import load_config, validate_config
from shared.logging import configure_logging
from shared.powershell import PowerShellError, ScriptTimeoutError, WinRMPowerShellRunner, to_json

bp = func.Blueprint()


@bp.route(route="migrate", methods=["POST"])
def migrate(req: func.HttpRequest) -> func.HttpResponse:
    configure_logging()
    try:
        request = migration_request_from_dict(req.get_json())
        config = load_config()
        validate_config(config)

        # Generate a single unique dMSA name shared across all operations
        unique_suffix = str(int(time.time()))[-5:]
        unique_dmsa_name = f"{request.dmsa_name}-{unique_suffix}"

        # Create-DMSA.ps1 uses the AD module — run on the Domain Controller
        dc_runner = WinRMPowerShellRunner(
            request.domain_controller, config, request.domain_controller_thumbprint)
        # Configure-WindowsService.ps1 modifies the local SCM — run on the Member Server
        member_runner = WinRMPowerShellRunner(
            request.target_host, config, request.target_host_thumbprint)

        create_result = create_dmsa(dc_runner, request, unique_dmsa_name)
        migration_result = migrate_service(member_runner, request, unique_dmsa_name)
        netbios_domain = request.domain_dns_name.split('.')[0].upper()
        validation_result = validate_service(
            member_runner, request.service_name, f"{netbios_domain}\\{unique_dmsa_name}$")
        return func.HttpResponse(
            to_json(
                {
                    "create": create_result,
                    "migration": migration_result,
                    "validation": validation_result,
                }
            ),
            mimetype="application/json",
        )
    except (ValueError, PowerShellError) as exc:
        logging.exception("migration failed")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=400, mimetype="application/json")
    except ScriptTimeoutError as exc:
        logging.exception("migration timed out")
        return func.HttpResponse(to_json({"error": str(exc)}), status_code=504, mimetype="application/json")