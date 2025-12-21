# project-eventgrid-partnerconfiguration — Entra Event Grid → Lifecycle Governance (Detect + Auto-Remediate)

This project is a reference pattern for **identity access/governance management** that uses **Microsoft Entra as an Event Grid partner** (Partner Configuration) to stream identity lifecycle signals into Azure, and an **Azure Function App** to **detect + auto-remediate** entitlement hygiene issues.

The core idea: **treat identity changes as events**, apply policy in code, and automatically clean up high-risk access in near-real time.

## Scenario summary

- **Source**: Microsoft Entra events delivered through **Azure Event Grid Partner Configuration**
- **Compute**: Azure Functions (Event Grid trigger)
- **Governance objective**: Keep entitlements correct as users and principals change (joiner/mover/leaver), and reduce risk by automatically removing privileged/high-risk access when policy conditions are met

## What this project does

### Event-driven detections (examples)

The Function processes Entra-originated events (via Event Grid) such as:

- **Leaver/termination-like signals**
  - User disabled
  - User deleted
- **Joiner signals**
  - user created delta
- **Entitlement changes**
  - Group membership changes

> Exact event types depend on what Entra publishes through the partner integration and what you subscribe to. This repo is structured so you can start small and expand.

### Auto-remediation actions (guardrail-driven)

When conditions match policy, the Function can automatically:

- Apply birthright access (where applicable)
- Revoke user sessions / sign-in refresh (where supported)
- Remove user from **high-risk groups** (configured allowlist/denylist)
- Remove or disable **privileged assignments** (where supported)
- Remove app role assignments to sensitive apps (optional)
- Write a governance audit record (App Insights + optional storage)

**Safety defaults** (recommended):

- Start with _detect-only_ in non-prod and enable remediation per policy rule.
- Require explicit allowlists for what can be modified (groups, roles, apps).

## High-level architecture

1. **Entra → Event Grid Partner Configuration**

- You configure an Event Grid **partner configuration** in your subscription/region.
- Entra publishes supported event types into Event Grid as a partner source.

2. **Event Grid Subscription**

- You create Event Grid subscriptions that route selected event types to your Function endpoint.

3. **Azure Function App (Event Grid Trigger)**

- Receives events
- Validates event authenticity (Event Grid validation handshake / signature behavior as applicable)
- Deduplicates (idempotency)
- Responds to subscription lifecycle notifications events
- Looks up additional context from Microsoft Graph if needed
- Applies policy and performs remediation
- 

4. **Microsoft Graph (Entra ID OAuth)**

- Function uses **Entra ID OAuth (client credentials)** to:
  - read user/principal details for policy decisions
  - apply remediation actions (remove memberships/assignments, revoke sessions) where supported

5. **Observability**

- Application Insights traces each event handling run with correlation IDs
- Optional: persist “governance decisions” to storage for reporting

## Policy model (recommended)

Keep policies explicit, versionable, and safe:

- **Rule inputs**

  - event type
  - principal type (user/service principal)
  - principal properties (enabled/disabled, department, etc.)
  - resource impacted (group/role/app)

- **Rule outputs**

  - action: `none | notify | remediate`
  - remediation steps (remove from group, revoke sessions, etc.)
  - severity and rationale

- **Guardrails**
  - allowlists for groups/roles/apps that automation may modify
  - “break-glass” exclusions (accounts never modified)
  - maximum actions per event (to prevent runaway loops)

## Idempotency + replay handling

Event delivery is at-least-once.

- Compute a stable `dedupeKey` from event metadata (e.g., event `id` + `eventType` + `subject`).
- Store processed keys for a short TTL (e.g., storage table/redis) to avoid duplicates.
- Ensure remediation operations are safe to repeat (e.g., removing a user from a group should be treated as success even if already removed).

## Security posture

### Authentication

- **Graph access**: Entra ID OAuth (client credentials)
  - App Registration or Managed Identity (preferred if supported for your chosen Graph flows)
  - Secrets/certs stored in Key Vault

### Authorization

- Least-privilege Graph application permissions (read + only the write actions you truly need)
- Restrict which resources can be mutated (allowlists)

### Network

- Keep the Function endpoint accessible to Event Grid.
- For hardened setups, use private networking patterns if compatible with Event Grid delivery requirements.

## Project layout (intended)

- `infra/` — Bicep templates for:
  - Event Grid partner configuration + subscriptions
  - Function App + hosting dependencies
  - Key Vault + App Insights
- `src/` — Azure Functions:
  - Event Grid trigger handler
  - Policy evaluation
  - Graph client + remediation operations
- `scripts/` — helpers for:
  - app registration and permission grants
  - local configuration
  - smoke tests and sample events
- `docs/` — governance policies and runbooks

## Deployment flow (high level)

1. **Create partner configuration** in Azure Event Grid for Entra as a partner.
2. **Deploy Function App** (with identity + Key Vault + App Insights).
3. **Create Event Grid subscription(s)** targeting the Function endpoint.
4. **Configure Entra app permissions** (Graph) required for reads + chosen remediations.
5. **Configure policies** (allowlists, exclusions, thresholds).
6. Start in **detect-only** mode, then enable **auto-remediation** rule-by-rule.

## Operational guidance

- Always log: event id, event type, principal id, resource id, policy rule matched, remediation outcome.
- Prefer “small blast radius” policies first (e.g., revoke sessions on disable, remove from a single high-risk group set).
- Maintain a manual break-glass process for exceptions.

## MVP scope (recommended first increment)

- Event ingestion + validation + dedupe
- Policy engine with:
  - Break-glass exclusions
  - Group allowlist for removals
- Remediations:
  - On user disabled: revoke sessions, remove from configured high-risk groups
- Observability: App Insights logs + a simple daily summary

---

If you want, I can scaffold the folder structure (`infra/`, `src/`, `scripts/`, `docs/`) and add a minimal Azure Functions starter (Event Grid trigger + Graph auth stub) aligned to this outline.
