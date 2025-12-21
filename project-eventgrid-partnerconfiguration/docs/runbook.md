# Runbook (detect → auto-remediate)

## 1) Deploy infrastructure

- Deploy partner configuration and (optionally) event subscriptions in `infra/`.
- Ensure Event Grid can reach your Function endpoint.

## 2) Configure Graph access

- Create an Entra ID app registration used by the Function.
- Grant only the minimal Microsoft Graph application permissions required for:
  - reading principal context
  - performing the specific remediation steps you enable

## 3) Start in detect mode

- Set `MODE=detect` in Function App settings.
- Verify events are received and logged.

## 4) Enable remediation safely

- Populate allowlists for groups/roles/apps that can be modified.
- Add break-glass exclusions.
- Switch to `MODE=remediate` only after validation.

## 5) Incident response

- If a policy causes unexpected changes:
  - revert to `MODE=detect`
  - expand break-glass list
  - investigate logs by `dedupeKey`
