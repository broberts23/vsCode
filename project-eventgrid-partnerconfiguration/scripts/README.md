# scripts

PowerShell 7.4 helper scripts for deploying and operating the sample.

- Scripts in this folder are intended to run locally or in CI.
- They should not embed secrets; use Key Vault or environment variables.

Planned scripts in this scaffold:
- `Deploy-Infrastructure.ps1` — deploy Bicep
- `Set-Policy.ps1` — validate/publish policy configuration
- `SmokeTest-GraphAuth.ps1` — verify Graph auth from your workstation
