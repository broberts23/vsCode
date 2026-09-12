# The Application Registration Vending Machine

It been been a hot minute between blogs. Since the last blog, I've studing for the new [Microsoft 365 Certified: Microsoft 365 and AI Services Administrator Associate (beta) AB-650](https://learn.microsoft.com/en-us/credentials/certifications/ai-services-administrator-associate/?wt.mc_id=credentials_AB650_blog_wwl\&practice-assessment-type=certification) - still waiting to here if i passed 🫤 - studying for and passing the new [Microsoft Certified: Cloud and AI Security Engineer Associate SC-500](https://learn.microsoft.com/en-us/credentials/certifications/cloud-and-ai-security-engineer-associate/?practice-assessment-type=certification) exam and renewing my [GCP Associate Cloud Engineer](https://cloud.google.com/learn/certification/cloud-engineer) certification for another 12 months.

But now it's back into the practical work!

Every identity engineer has lived through the same Tuesday afternoon. A ServiceNow ticket lands in the queue asking for a new application registration. The requester wants HR.Read and HR.Write app roles, a redirect URI that might or might not be correct, and somewhere in the comments someone wrote "needs MFA" without specifying whether that means user MFA, compliant device, or something else entirely. You open the Entra portal, click through six blades, paste a redirect URI, create two app roles by hand, generate a client secret because the team asked for one, and then realize nobody thought about Conditional Access until production week.

This project exists because that workflow does not scale, and more importantly, it does not teach you the patterns you need for a serious identity engineering career.

## Why a vending machine

The core idea is borrowed from a pattern you already know if you have worked with cloud platform teams: callers do not design infrastructure from scratch. They pick a SKU. The SKU encodes the security posture. The vending service enforces it.

An application registration vending machine applies the same discipline to Entra ID. Callers submit a small payload — an offering ID, a display name, owners, a justification, and instance-specific parameters. They do not choose arbitrary Graph permissions, arbitrary redirect URI patterns, or arbitrary Conditional Access grant controls. Those decisions live in a catalog file that identity engineering owns and reviews.

That constraint is the whole point. It is what makes the system governable, auditable, and safe to expose to an ITSM integration.

## Prerequisites as code, not portal clicks

Here is the trap that kills most identity automation demos. You write a beautiful vending pipeline, then the README quietly says "first create an app registration, add two app roles, create a managed identity, grant Application.ReadWrite.OwnedBy and Policy.ReadWrite.ConditionalAccess, wire Easy Auth, and admin-consent everything." That is twenty portal clicks before the first request. It also contradicts the story you are selling. If the vending machine exists to stop handcrafting Entra objects, the foundation of the vending machine should not be handcrafted either.

The Bicep template in this repo uses the Microsoft Graph extension so the prerequisite identity plane is declared next to the Azure resources. One deployment creates the API application registration, stamps `AppVending.Submitter` and `AppVending.Admin` onto it, creates the enterprise application, provisions a user-assigned managed identity for the worker, and assigns the Graph application permissions that Live mode needs. Easy Auth on the Web App is wired to the generated client ID automatically. There is no leftover `easyAuthClientId` parameter for someone to paste from a screenshot.

```bicep
extension microsoftGraphV1

resource apiAppRegistration 'Microsoft.Graph/applications@v1.0' = {
  displayName: apiAppRegistrationName
  uniqueName: apiAppUniqueName
  signInAudience: 'AzureADMyOrg'
  identifierUris: [ apiAudience ]
  appRoles: [
    {
      allowedMemberTypes: [ 'User', 'Application' ]
      displayName: 'App Vending Submitter'
      id: submitterRoleId
      isEnabled: true
      value: 'AppVending.Submitter'
    }
    // AppVending.Admin follows the same shape
  ]
}

resource workerGraphAppReadWriteOwnedBy 'Microsoft.Graph/appRoleAssignedTo@v1.0' = {
  appRoleId: '18a4783c-866b-4cc7-a460-3d5e5662c884' // Application.ReadWrite.OwnedBy
  principalId: workerIdentity.properties.principalId
  resourceId: microsoftGraphServicePrincipal.id
}
```

After deployment, the Azure resource group should look like a complete platform slice rather than a half-finished lab: Web App, Function App, Storage Account, Application Insights, App Service plans, and the worker managed identity sitting together.

![Azure resource group overview after Bicep deploy](docs/screenshots/01-azure-resource-group.png)

In the Entra admin center, the API app registration shows the two application roles that gate the ITSM API. Those roles are not decorative documentation. They become claims in the access token and the FastAPI dependency rejects callers that lack them.

![Entra API app registration app roles](docs/screenshots/02-entra-api-app-roles.png)

The worker identity's Microsoft Graph permissions should show `Application.ReadWrite.OwnedBy`, `Policy.Read.All`, and `Policy.ReadWrite.ConditionalAccess` with admin consent. That is the least-privilege set Live mode needs to create owned applications and report-only Conditional Access policies. If your deploying account cannot grant Graph application permissions, set `assignWorkerGraphPermissions=false` in the parameters file and run `scripts/Grant-WorkerGraphPermissions.ps1` with a privileged identity afterward.

![Worker managed identity Graph permissions](docs/screenshots/03-entra-worker-graph-permissions.png)

## The ITSM contract

Real ITSM systems do not wait around while you click through the Entra portal. They open a ticket, call an API, get an immediate acknowledgement, and move on. When provisioning finishes, they want a callback with the object IDs and next steps.

The API implements exactly that pattern. `POST /v1/requests` validates the payload, writes the request to Azure Table Storage with status `accepted`, drops a message on a Storage Queue, and returns `202 Accepted` with a `requestId` and a `statusUrl`. The queue-triggered worker picks up the job, runs the vend pipeline, updates the table row, and POSTs the completion payload to the `callbackUrl` if one was supplied.

Callers that cannot receive webhooks can poll `GET /v1/requests/{requestId}` instead. Both paths read the same table row. The design is intentionally boring, which is a compliment.

Swagger UI at `/docs` gives you an interactive surface for development and testing. In production, ServiceNow or another ITSM calls the same endpoints with a Bearer token obtained through OAuth 2.0 authorization code flow with PKCE.

![Swagger POST /v1/requests returning 202 Accepted](docs/screenshots/04-swagger-202-accepted.png)

When the worker is running, the queue message disappears from `vend-jobs` and the Function host logs the vend job identifier. That terminal line is the proof that identity provisioning left the synchronous request path.

![Function worker dequeueing vend-jobs](docs/screenshots/05-function-worker-dequeue.png)

## Authentication layers

The auth model stacks four layers, each teaching a different exam and career skill.

Callers authenticate with OAuth 2.0 authorization code plus PKCE. The included `scripts/get_token_pkce.py` script is deliberately small — MSAL, a localhost callback handler, and a printed Bearer token. No framework, no wrapper classes.

The FastAPI Web App sits behind Easy Auth in Azure, configured through Bicep `authsettingsV2`. Easy Auth validates the JWT at the platform edge before your Python code runs. After deploy, the Authentication blade should show the Microsoft identity provider pointing at the Bicep-created application and returning HTTP 401 for unauthenticated clients.

![Azure Web App Easy Auth configuration](docs/screenshots/09-azure-easy-auth.png)

Inside the API, a dependency checks app role claims. Callers need `AppVending.Submitter` or `AppVending.Admin`. Roles come from the API's own app registration, not from group membership checked at runtime. That is RBAC done the Entra way.

The worker Function App uses a user-assigned managed identity to call Microsoft Graph in Live mode. No client secrets stored in configuration. `DefaultAzureCredential` resolves to that identity in Azure through `AZURE_CLIENT_ID`, and to your developer credential locally.

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

Switch `APP_VENDING_EXECUTION_MODE` to `Live` when you are ready. The worker creates the application, assigns owners when the object IDs are valid, creates the service principal, and posts the Conditional Access policy through Graph. Report-only state is the default so you can validate impact before enforcement.

After Live mode succeeds, open Microsoft Entra ID, find the new app registration by display name, and inspect the SPA redirect URI plus the `HR.Read` and `HR.Write` app roles. That portal blade is the moment the catalog stops being theory.

![Vended HR SPA app registration in Entra](docs/screenshots/06-entra-vended-hr-app.png)

The matching Conditional Access policy should appear in report-only mode with the compliant device grant control. Leave it there while you review sign-in logs. Promotion to enabled is a deliberate second step, not an accidental side effect of vending.

![Report-only Conditional Access policy for HR portal](docs/screenshots/08-entra-ca-report-only.png)

## CAE and a one-hour session for payroll

Default Entra access tokens last a variable sixty to ninety minutes. That window is the blast radius of a stolen bearer token if nothing else is watching. Continuous Access Evaluation changes the bargain. When a client declares the `cp1` capability and the resource is CAE-aware, Entra can issue a long-lived token, often measured in hours rather than minutes, because critical events such as a disabled account, a password change, or a Conditional Access location change can revoke access near real time through a claims challenge. Without a session ceiling, a privileged payroll API that opts into CAE would actually hold tokens longer than the default.

That is why the `privileged-payroll-api` SKU does two things at once. The vended application is stamped for CAE with access token version two and the optional claim `xms_cc`, so tokens can carry the client capability that makes claims challenges possible. The Conditional Access policy that accompanies the app requires a compliant device, scopes itself to that application rather than every cloud app in the tenant, and sets session controls that identity engineers can see in the portal: a one-hour sign-in frequency and Continuous Access Evaluation in `strictEnforcement` mode.

```json
{
  "offeringId": "privileged-payroll-api",
  "displayName": "Payroll API - Prod",
  "owners": ["11111111-1111-1111-1111-111111111111"],
  "justification": "ServiceNow REQ009001",
  "callbackUrl": "https://itsm.contoso.com/api/hooks/vend-complete",
  "parameters": {}
}
```

The catalog does not invent a directory `tokenLifetimePolicy`. Microsoft's current guidance points operators at Conditional Access session management for how often users must re-authenticate, and at CAE for event-driven revocation. Token lifetime policies are Graph-only with no Entra admin center blade. Sign-in frequency lives on the same Conditional Access policy the identity team already reviews, and Graph v1.0 expresses it in hours or days, so this SKU uses one hour rather than a fifteen-minute JWT `exp`. Sub-hour access-token lifetimes would require the token lifetime policy this project deliberately avoids.

```json
"sessionControls": {
  "signInFrequency": {
    "isEnabled": true,
    "type": "hours",
    "value": 1,
    "frequencyInterval": "timeBased"
  },
  "continuousAccessEvaluation": {
    "mode": "strictEnforcement"
  }
}
```

The vending machine prepares the resource app. Callers still have to declare `cp1` when they request tokens, for example with MSAL client capabilities, and the payroll API still has to handle a 401 claims challenge. DryRun shows the optional claim and the session controls in the receipt. Live mode creates the application, then posts the Conditional Access policy through the Graph beta endpoint so the Continuous Access Evaluation block is not dropped.

![Privileged payroll Conditional Access Session blade](docs/screenshots/11-cae-signin-frequency.png)

![Payroll app optional claim xms_cc](docs/screenshots/12-app-xms-cc-optional-claim.png)

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

![AKS federated credential on the vended application](docs/screenshots/07-entra-aks-federated-credential.png)

## UTCM guardrails

Creating a Conditional Access policy is only half the job. Policies drift. Someone disables one during an incident and forgets to re-enable it. UTCM — Unified Configuration Management — gives you a monitor artifact that describes the desired state and runs on a schedule to detect drift.

After each vend job, `utcm.py` renders a monitor JSON file from the catalog's `baselineRef` template, stamps it with the policy display name from the vend result, and writes it to `samples/utcm/generated/`. The callback payload includes `utcmMonitorArtifact` with the relative path. You can feed that artifact into your existing UTCM deployment scripts to register ongoing monitoring.

![Generated UTCM monitor artifact in VS Code](docs/screenshots/10-utcm-monitor-artifact.png)

Vending and drift detection become one pipeline instead of two disconnected processes.

## Local development without Azure spend

The entire DryRun path still runs locally with three terminals and zero Azure resources beyond what you already have installed. Start Azurite for queue and table emulation. Run the FastAPI API with `uvicorn api.main:app --reload`. Run the Functions worker with `func start` from the `worker/` directory. Post a request from Swagger or curl. Watch the worker dequeue the job, write the completed result to the emulated table, and optionally fire the callback.

When you are ready for portal evidence, deploy the Bicep stack, leave execution mode on DryRun until Graph permissions show consent, then flip `APP_VENDING_EXECUTION_MODE` to Live and vend into a non-production tenant. The local loop teaches the contract. The Azure and Entra blades prove the contract survived contact with a real directory.

## Python philosophy

The shared code in `src/app_vending/` follows a strict KISS rule: plain functions in modules, no service classes, no repository abstractions. Pydantic models exist only at the API boundary for request validation and OpenAPI generation. Graph calls use `httpx` and `msal` directly. Well-known Microsoft Graph permission IDs are mapped in a small dictionary so Live `requiredResourceAccess` payloads stay valid. Invalid owner object IDs log a warning and are skipped instead of failing the whole vend job. If you can read one function top to bottom and understand what it does, the code is doing its job.

## What this teaches for your career

OAuth 2.0 and PKCE show up in the client token script and in the SPA SKU definition. App roles and Easy Auth appear in the API authorization path. Managed identity and least-privilege Graph permissions matter in Live mode. Conditional Access templates cover user-facing apps, privileged sessions with Continuous Access Evaluation, and workload identities. Microsoft Graph Bicep makes the prerequisite identity plane reviewable in pull requests. UTCM ties provisioning to ongoing compliance. The async queue-and-callback pattern mirrors how real enterprise integrations work with ServiceNow, BMC, and other ITSM platforms.

That is a full identity engineering pipeline in one repo, runnable on your laptop, deployable to cheap Azure resources, and visible in the Entra portal when Live mode does the work that used to consume your Tuesday afternoon.
