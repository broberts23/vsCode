from typing import Any

from shared.models import MigrationRequest, RollbackRequest


def migration_request_from_dict(value: dict[str, Any]) -> MigrationRequest:
    return MigrationRequest(
        service_name=_required(value, "serviceName"),
        dmsa_name=_required(value, "dmsaName"),
        target_host=_required(value, "targetHost"),
        domain_controller=_required(value, "domainController"),
        domain_dns_name=_required(value, "domainDnsName"),
        previous_account=value.get("previousAccount"),
        superseded_account=value.get("supersededAccount"),
        domain_controller_thumbprint=value.get("domainControllerThumbprint"),
        target_host_thumbprint=value.get("targetHostThumbprint"),
    )


def rollback_request_from_dict(value: dict[str, Any]) -> RollbackRequest:
    return RollbackRequest(
        service_name=_required(value, "serviceName"),
        previous_account=_required(value, "previousAccount"),
        target_host=_required(value, "targetHost"),
        dmsa_name=value.get("dmsaName"),
        domain_controller=value.get("domainController"),
        superseded_account=value.get("supersededAccount"),
        domain_controller_thumbprint=value.get("domainControllerThumbprint"),
        target_host_thumbprint=value.get("targetHostThumbprint"),
    )


def _required(value: dict[str, Any], key: str) -> str:
    result = value.get(key)
    if result is None or str(result).strip() == "":
        raise ValueError(f"Missing required field: {key}")
    return str(result)