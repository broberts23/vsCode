from dataclasses import dataclass, field


@dataclass(frozen=True)
class WindowsService:
    name: str
    display_name: str
    start_name: str
    state: str


@dataclass(frozen=True)
class InventoryResult:
    host: str
    services: list[WindowsService] = field(default_factory=list)


@dataclass(frozen=True)
class MigrationRequest:
    service_name: str
    dmsa_name: str
    target_host: str
    domain_controller: str
    domain_dns_name: str
    previous_account: str | None = None
    superseded_account: str | None = None
    domain_controller_thumbprint: str | None = None
    target_host_thumbprint: str | None = None


@dataclass(frozen=True)
class MigrationResult:
    service_name: str
    dmsa_name: str
    changed: bool
    message: str


@dataclass(frozen=True)
class ValidationResult:
    service_name: str
    running: bool
    account: str
    message: str


@dataclass(frozen=True)
class RollbackRequest:
    service_name: str
    previous_account: str
    target_host: str
    dmsa_name: str | None = None
    domain_controller: str | None = None
    superseded_account: str | None = None
    domain_controller_thumbprint: str | None = None
    target_host_thumbprint: str | None = None


@dataclass(frozen=True)
class RollbackResult:
    service_name: str
    restored_account: str
    changed: bool
    message: str
