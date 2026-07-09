# Project 1 -- dMSA Migration Factory

## Overview

Build a Python Azure Functions v2 application that inventories Windows
services, creates delegated Managed Service Accounts (dMSAs), migrates
services, validates operation, and supports rollback.

**Project Size**: This project should be at the PoC/lab level. Rigorous unit testing and extensive documentation are not required.

## Assumptions

- Azure infrastructure already exists.
- Windows Server 2025 VM is domain joined.
- AD DS role installed.
- WinRM/PowerShell remoting configured.
- The prebuild lab setup generates certificates and part of the server/function app deployment.

## Coding Agent Instructions

### Goals

- Use Python 3.12 Azure Functions v2 programming model.
- Debug locally with `func start`.
- Keep modules small.
- Prefer dataclasses for models.
- Avoid unnecessary wrapper classes.
- One responsibility per module.

### Authentication & WinRM

- **Transport**: Projects should target a remote PowerShell (WinRM) over TLS connection.
- **Certificate Configuration**: In this lab environment, certificate pinning to the private key on the VM should be used while skipping CA (Certificate Authority) and revocation checks.
  - *Extra Detail*: Because self-signed or lab-generated certificates are used, skipping CA checks prevents connection failures. You will configure your Python WinRM library (e.g., `pywinrm` with `requests_ntlm` or `requests_credssp`, passing `cert_validation='ignore'` or appropriately disabling `verify` while matching the certificate thumbprint/private key) to trust the specific connection.
- **Service Accounts**: Ensure the service account utilized by the function app has the requisite Active Directory privileges (to create dMSAs) and local administrative rights on the VM (to restart services and configure logons).

### Suggested structure

``` text
function_app.py
host.json
local.settings.json
requirements.txt
shared/
  config.py
  logging.py
  powershell.py
  models.py
functions/
  inventory.py
  migrate.py
  validate.py
  rollback.py
domains/
  inventory.py
  migration.py
  validation.py
contracts/
  inventory.py
  migration.py
scripts/
  Create-DMSA.ps1
  Install-ADServiceAccount.ps1
  Configure-WindowsService.ps1
  Restart-ValidateService.ps1
tests/
```

### Contracts

- InventoryResult
- MigrationRequest
- MigrationResult
- ValidationResult

### Functions

- discover_services()
- create_dmsa()
- migrate_service()
- validate_service()
- rollback_service()

### PowerShell responsibilities

- Use separate `.ps1` files for maintainability instead of embedding scripts inline in Python code.
- **Active Directory management**: dMSA creation must be performed using the Windows Server Active Directory PowerShell module (e.g., `New-ADServiceAccount`).
- Install AD service account.
- Configure Windows Service logon.
- Restart and validate service.

### Testing

- Basic unit testing only.
- Unit-test domain logic.
- Mock PowerShell execution.

### Documentation & Blog

- **README.md**: Include only a README.md capturing the technical details of the project and how to use it.
- **Blog Skeleton**: Include the skeleton of a blog series. The blog should be a narrative explanation of the technology and processes.
- **Blog Series Format**: Each blog should capture both projects. Do not break down the blog into sub-projects.
