# The Application Registration Vending Machine

Every identity engineer has lived through the same Tuesday afternoon. A ServiceNow ticket lands in the queue asking for a new application registration. The requester wants HR.Read and HR.Write app roles, a redirect URI that might or might not be correct, and somewhere in the comments someone wrote "needs MFA" without specifying whether that means user MFA, compliant device, or something else entirely. You open the Entra portal, click through six blades, paste a redirect URI, create two app roles by hand, generate a client secret because the team asked for one, and then realize nobody thought about Conditional Access until production week.

This project exists because that workflow does not scale, and more importantly, it does not teach you the patterns you need for a serious identity engineering career.

## Why a vending machine

The core idea is borrowed from a pattern you already know if you have worked with cloud platform teams: callers do not design infrastructure from scratch. They pick a SKU. The SKU encodes the security posture. The vending service enforces it.

An application registration vending machine applies the same discipline to Entra ID. Callers submit a small payload — an offering ID, a display name, owners, a justification, and instance-specific parameters. They do not choose arbitrary Graph permissions, arbitrary redirect URI patterns, or arbitrary Conditional Access grant controls. Those decisions live in a catalog file that identity engineering owns and reviews.

That constraint is the whole point. It is what makes the system governable, auditable, and safe to expose to an ITSM integration.

## The ITSM contract

Real ITSM systems do not wait around while you click through the Entra portal. They open a ticket, call an API, get an immediate acknowledgement, and move on. When provisioning finishes, they want a callback with the object IDs and next steps.

The API implements exactly that pattern. `POST /v1/requests` validates the payload, writes the request to Azure Table Storage with status `accepted`, drops a message on a Storage Queue, and returns `202 Accepted` with a `requestId` and a `statusUrl`. The queue-triggered worker picks up the job, runs the vend pipeline, updates the table row, and POSTs the completion payload to the `callbackUrl` if one was supplied.

Callers that cannot receive webhooks can poll `GET /v1/requests/{requestId}` instead. Both paths read the same table row. The design is intentionally boring, which is a compliment.

Swagger UI at `/docs` gives you a interactive surface for development and testing. In production, ServiceNow or another ITSM calls the same endpoints with a Bearer token obtained through OAuth 2.0 authorization code flow with PKCE.

## Authentication layers

The auth model stacks four layers, each teaching a different exam and career skill.

Callers authenticate with OAuth 2.0 authorization code plus PKCE. The included `scripts/get_token_pkce.py` script is deliberately small — MSAL, a localhost callback handler, and a printed Bearer token. No framework, no wrapper classes.

The FastAPI Web App sits behind Easy Auth in Azure, configured through Bicep `authsettingsV2` the same way your agent vending machine scaffold does. Easy Auth validates the JWT at the platform edge before your Python code runs.

Inside the API, a dependency checks app role claims. Callers need `AppVending.Submitter` or `AppVending.Admin`. Roles come from the API's own app registration, not from group membership checked at runtime. That is RBAC done the Entra way.

The worker Function App uses a system-assigned managed identity to call Microsoft Graph in Live mode. No client secrets stored in configuration. `DefaultAzureCredential` resolves to managed identity in Azure and to your developer credential locally.

For local development, set `AUTH_BYPASS=true` and skip token acquisition until you are ready to test the full auth path.

## Walkthrough: internal HR SPA

A typical request looks like this:

```json
{
  "offeringId": "internal-hr-spa",
  "displayName": "HR Internal Portal - Prod",
  "owners": ["11111111-1111-1111-1111-111111111111"],
  "justification": "ServiceNow REQ001234",
  "callbackUrl": "https://itsm.contoso.com/api/hooks/vend-complete",
  "parameters": {}
}
```

The `internal-hr-spa` SKU in the catalog defines a single-page application using authorization code with PKCE, two app roles (`HR.Read` and `HR.Write`), no client secret, and a Conditional Access template requiring compliant devices in report-only mode.

In DryRun mode, which is the default, the worker never calls Graph. It returns a `dryRunPlan` showing exactly what would be created: the application body with app roles and SPA redirect URIs, the service principal plan, the Conditional Access policy object, and the UTCM monitor artifact path. You can review the plan in the callback payload or by polling the status endpoint.

Switch `APP_VENDING_EXECUTION_MODE` to `Live` when you are ready. The worker creates the application, assigns owners, creates the service principal, and posts the Conditional Access policy through Graph. Report-only state is the default so you can validate impact before enforcement.

## Walkthrough: AKS Graph workload

The second SKU covers a different real-world shape entirely:

```json
{
  "offeringId": "aks-graph-workload",
  "displayName": "AKS Order Service - Graph Reader",
  "owners": ["22222222-2222-2222-2222-222222222222"],
  "justification": "ServiceNow REQ005678",
  "callbackUrl": "https://itsm.contoso.com/api/hooks/vend-complete",
  "parameters": {
    "aksServiceAccount": "system:serviceaccount:orders:order-api",
    "allowedIpRanges": "10.0.0.0/8"
  }
}
```

This SKU provisions a web platform application configured for client credentials, a federated identity credential pointing at the AKS OIDC issuer, `User.Read.All` as an application permission, a certificate credential strategy, and a workload Conditional Access template with IP range restrictions. The `parameters` block fills template placeholders in the catalog — `{{parameters.aksServiceAccount}}` becomes the federated credential subject, and `{{parameters.allowedIpRanges}}` flows into the CA policy conditions.

That is the pattern for service-to-service identities in Kubernetes: the vending machine creates the Entra objects, and the platform team wires the federated credential subject to the service account. Identity engineering owns the posture. Platform engineering owns the pod.

## UTCM guardrails

Creating a Conditional Access policy is only half the job. Policies drift. Someone disables one during an incident and forgets to re-enable it. UTCM — Unified Configuration Management — gives you a monitor artifact that describes the desired state and runs on a schedule to detect drift.

After each vend job, `utcm.py` renders a monitor JSON file from the catalog's `baselineRef` template, stamps it with the policy display name from the vend result, and writes it to `samples/utcm/generated/`. The callback payload includes `utcmMonitorArtifact` with the relative path. You can feed that artifact into your existing UTCM deployment scripts to register ongoing monitoring.

Vending and drift detection become one pipeline instead of two disconnected processes.

## Local development without Azure spend

The entire DryRun path runs locally with three terminals and zero Azure resources beyond what you already have installed.

Start Azurite for queue and table emulation. Run the FastAPI API with `uvicorn api.main:app --reload`. Run the Functions worker with `func start` from the `worker/` directory. Post a request from Swagger or curl. Watch the worker dequeue the job, write the completed result to the emulated table, and optionally fire the callback.

The VS Code launch configuration starts both the API and the worker together. The tasks file includes an Azurite starter. Copy `worker/local.settings.sample.json` to `local.settings.json` and you are running.

## Python philosophy

The shared code in `src/app_vending/` follows a strict KISS rule: plain functions in modules, no service classes, no repository abstractions. Pydantic models exist only at the API boundary for request validation and OpenAPI generation. Graph calls use `httpx` and `msal` directly. If you can read one function top to bottom and understand what it does, the code is doing its job.

## What this teaches for your career

OAuth 2.0 and PKCE show up in the client token script and in the SPA SKU definition. App roles and Easy Auth appear in the API authorization path. Managed identity and least-privilege Graph permissions matter in Live mode. Conditional Access templates cover both user-facing apps and workload identities. UTCM ties provisioning to ongoing compliance. The async queue-and-callback pattern mirrors how real enterprise integrations work with ServiceNow, BMC, and other ITSM platforms.

That is a full identity engineering pipeline in one repo, runnable on your laptop, deployable to cheap Azure resources when you are ready to go further.
