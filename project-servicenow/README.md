# project-servicenow — Identity Governance Signals → ServiceNow Work (Entra ID + Azure Functions)

This project is a reference pattern for turning **Entra ID identity governance signals** into **actionable ServiceNow work items** (incidents/tasks/HR cases) using **Azure Function Apps** and **Microsoft Graph**.

It is designed to run against a **ServiceNow Developer (Personal Dev Instance)** and uses **Entra ID OAuth** for secure access to Microsoft Graph and for protecting any HTTP-triggered automation endpoints.

## What this project does

- Polls or receives identity governance signals from Entra ID (via Microsoft Graph)
- Normalizes signals into a small set of remediation “work types”
- Creates or updates ServiceNow records with ownership, due dates, and evidence links
- Tracks lifecycle (open → in progress → resolved) and writes closure state back to the signal source when applicable
- Produces audit logs suitable for governance reporting

## Example signals (starting scope)

This repo starts with three signal types and their corresponding ServiceNow work patterns.

- **Privileged drift**
  - New/changed privileged assignment detected → create/update `sn_task` (or `incident`) routed to the identity governance team
  - Record includes _who_, _what role_, _scope_, _when detected_, and suggested remediation steps
- **Access reviews status**
  - Review not started / overdue → create/update `sn_task` assigned to reviewer group (or application owner group)
  - Review completed with “Remove” decisions (optional) → create a verification task to confirm deprovisioning
- **Orphaned privileged assignments**
  - Privileged assignment where the principal no longer exists / is disabled / is unlicensed (your definition) → create/update `sn_task`
  - Prioritize by role criticality and age of assignment

## High-level architecture

1. **Azure Function App (Timer Trigger)** runs on a schedule (e.g., every 15 minutes):

   - Calls Microsoft Graph using **Entra ID OAuth (client credentials)**
   - Retrieves configured signal types
   - Correlates signals to existing ServiceNow records (idempotent upsert)

2. **Azure Function App (HTTP Trigger, optional)** for manual run / troubleshooting:

   - Protected by **Entra ID OAuth** (bearer tokens issued by your tenant)
   - Useful for “run now” and controlled reprocessing

3. **ServiceNow Dev Instance** stores and routes work:
   - Receives creates/updates via ServiceNow REST APIs (Table API)
   - Assigns to groups based on signal type, application ownership, or custom mapping

## Authentication & authorization (Entra ID OAuth)

### Graph access (required)

- Azure Function authenticates to Microsoft Graph using **client credentials**:
  - Entra ID App Registration (confidential client)
  - Secret or certificate (prefer certificate) stored in Key Vault
  - Least-privilege Graph application permissions for the chosen signals

### Function endpoint protection (optional but recommended)

- Any HTTP-triggered function endpoints use Entra ID authentication:
  - Configure Function App authentication (Easy Auth / App Service Authentication)
  - Require AAD-issued bearer tokens (client credential or delegated)
  - Restrict access to a specific app registration (audience) and optionally specific roles

### ServiceNow API access (required)

You will call ServiceNow REST APIs from the Function App.

- Simplest dev setup: ServiceNow local OAuth client (client id/secret) or basic auth for a dedicated integration user
- If you want “Entra ID OAuth end-to-end” for outbound calls:
  - Use an Entra ID App Registration representing the caller
  - Configure ServiceNow to validate tokens (depends on your instance capabilities and configuration)

This repo assumes **Entra ID OAuth for Graph + Function endpoint security** as the baseline. ServiceNow REST auth can start simple for a dev instance and be hardened later.

## Minimal data contract (signal → ServiceNow record)

Each created ServiceNow record should include:

- `short_description`: concise signal summary (e.g., “Access review overdue: Finance App Review Q1”)
- `description`: details, including identity, resource, timestamps, and recommended remediation
- `category` / `subcategory`: mapped from signal type
- `assignment_group` and/or `assigned_to`: mapped by policy
- `due_date`: derived from governance deadline
- Correlation fields:
  - `u_source_system` = `entra`
  - `u_source_type` = e.g., `accessReview|riskyUser|privilegedDrift`
  - `u_source_id` = stable signal identifier
  - `u_source_url` = link to Entra portal or Graph resource

> Note: `u_*` fields represent custom columns you add in ServiceNow. For a dev instance, prefer a small number of custom fields and keep everything else in `description`.

## Project layout (intended)

- `infra/` — Bicep templates for Function App, Key Vault, App Insights, storage, and auth configuration
- `src/` — Azure Functions code (HTTP + Timer triggers) and the ServiceNow client
- `scripts/` — setup helpers (app registration, permissions, local settings, smoke checks)
- `docs/` — governance mapping rules and runbooks (triage / remediation)

## Setup (ServiceNow dev instance)

1. Create a ServiceNow Personal Dev Instance and note your instance URL.
2. Create an **integration user** (dev-only) with least privileges to create/update target tables.
3. Decide the target table:
   - Start with `sn_task` or `incident` (easy)
   - Optionally use SecOps tables if enabled in your instance
4. Create minimal custom fields for correlation (recommended):
   - `u_source_system`, `u_source_type`, `u_source_id`, `u_source_url`
5. Create assignment rules:
   - Map signal type → assignment group
   - Map app/resource → owner group (optional)

## Setup (Azure / Entra ID)

1. Create an Entra ID App Registration for the Function App’s Graph calls.
2. Grant the minimal Microsoft Graph **application permissions** needed for the signals you selected.
3. Deploy an Azure Function App (Consumption or Premium) and configure:
   - Managed identity (recommended)
   - Key Vault references for secrets/certs
   - Application Insights
   - Timer schedule (e.g., every 15 minutes)
4. (Optional) Protect HTTP endpoints with Entra ID:
   - Enable App Service Authentication
   - Configure allowed audiences and issuer

## Configuration (conceptual)

These values typically live in Function App settings (Key Vault-backed where possible):

- `TENANT_ID`
- `GRAPH_CLIENT_ID`
- `GRAPH_CLIENT_SECRET` (or certificate reference)
- `SN_INSTANCE_URL`
- `SN_TABLE` (e.g., `sn_task`)
- `SN_AUTH_*` (depending on chosen ServiceNow auth approach)
- `SIGNAL_TYPES` (e.g., `accessReviews,riskyUsers`)
- `ASSIGNMENT_MAP` (simple JSON mapping signal type → group)

## Processing rules (idempotency)

To avoid duplicates:

- Build a deterministic **correlation key** from `(source_type, source_id)`
- On each run:
  - If a matching ServiceNow record exists → update it (status, assignment, notes)
  - Else → create a new record
- Only close ServiceNow work when the upstream signal is clearly remediated/closed

## Operational considerations

- Log all outbound calls with correlation IDs (but never log secrets)
- Rate limit Graph queries and handle paging
- Use a dead-letter / retry pattern for transient failures
- Keep a runbook for each signal type (“what to do when you get this ticket”)

## Roadmap (optional next increments)

- Bi-directional sync: close the governance item when ServiceNow task is resolved
- Evidence attachment: attach JSON snapshots to ServiceNow record
- Advanced routing: resource owner lookup via Graph / CMDB mapping
- ServiceNow Flow Designer: notify approvers or trigger downstream actions

---

If you want, I can scaffold the initial folder structure plus a starter Azure Functions app (Timer + optional HTTP trigger) and a small ServiceNow Table API client, keeping it minimal and aligned to this outline.
