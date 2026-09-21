# Stop mailing MyAccess into the void: access reviews that settle in Slack

## Hook

Recertification died in email again. The reminder landed, the week moved on, and the access review instance aged out while nobody opened MyAccess. In a real tenant you would chase reviewers in the portal. In **this** lab tenant there are no production users and no standing recertification program to poll — so the rest of this post injects Graph-shaped events on purpose, parks the human decision in Slack, and keeps Cosmos as the system of record for the demo.

<!-- screenshot: fixture JSON for ReviewOverdue next to the same fields on a Slack card -->

That honesty matters. The pattern still holds for production later: MyAccess stays the control plane, Graph becomes the `IAccessReviewClient` implementation, Slack stays the inbox. Today we prove the inbox without pretending the lab has telemetry it does not.

## Register the external app properly

Easy Auth on a Function you wrote does not count as the OIDC drill. Register a **PKCE SPA** and an **API** resource in Entra: redirect URIs, exposed scope `access_as_user`, authorized client, optional group claims. Validate issuer, audience, and scope in application code.

<!-- screenshot: Entra app registration Authentication blade with SPA redirect URIs -->

<!-- screenshot: Expose an API scope access_as_user -->

Break it once on purpose. Wrong redirect URI, `AADSTS50011`, then the fix. That screenshot is the muscle memory.

<!-- screenshot: browser error AADSTS50011 redirect URI mismatch, then the fix -->

Slack is **not** the IdP. Workspace login SSO is SAML and paid. Here Slack is an OAuth app: bot token, signing secret, Block Kit buttons. See `docs/slack-app.md` and `docs/entra-app-registrations.md`.

## Cheap AI-200 plane (no keys between Azure resources)

Container Apps Consumption (API + KEDA workers + cron simulator), Service Bus **Standard** topic with `slack-notify` / `apply-decision` subscriptions and DLQ, Cosmos **serverless** for correlation documents, ACR Basic, Key Vault, App Configuration Free, App Insights with 30-day retention.

Managed identity everywhere that Azure talks to Azure:

- Cosmos `disableLocalAuth: true`
- Service Bus `disableLocalAuth: true`
- ACR admin user off
- No storage account, no Functions, no WebJobs keys
- ACA settings carry **endpoints and names only**; Slack secrets are read from Key Vault via the same UAMI at runtime

<!-- screenshot: ACA environment revisions, UAMI assigned -->

<!-- screenshot: Service Bus topic with two subscriptions and DLQ depth -->

<!-- screenshot: Cosmos Data Explorer correlation document (redact identifiers) -->

<!-- screenshot: Azure portal Access control showing UAMI roles, and the Disabled local auth toggles on Cosmos and Service Bus -->

## Simulator to Slack

Fixtures live under `config/simulated-events/` (`ReviewPending`, `ReviewOverdue`, `ReviewReminderDue`, plus a poison payload). A Container Apps job replays them on a schedule; `POST /api/simulate` (OIDC) injects on demand so demos do not wait for cron.

<!-- screenshot: POST /simulate (or job log) publishing ReviewPending -->

<!-- screenshot: Slack card for a simulated pending review with Approve / Deny -->

## Human in Slack, apply is simulated

Click Approve. The API verifies the Slack signature, publishes `ApplyDecision` on the topic, and the apply worker updates Cosmos through `SimulatedAccessReviewClient`. No `PATCH` to Graph. No Entra decision blade to screenshot.

<!-- screenshot: Slack card updated to Applied -->

<!-- screenshot: Cosmos document status applied with the same correlation id -->

`GraphAccessReviewClient` exists as an empty stub with a comment. Wire it only when the tenant has P2, real review instances, and you are ready to grant Graph permissions you do not need for this lab.

## Portal still exists

The SPA signs in with **real** Entra OIDC and lists the simulated pending queue from Cosmos. Same inbox story, different surface.

<!-- screenshot: SPA sign-in redirect to Entra, then pending queue from Cosmos -->

## Failure path

Publish the poison fixture. The notify worker fails validation, abandons the message, and after max delivery count the DLQ has something you can peek. Trace one `correlationId` in App Insights / Log Analytics with KQL.

<!-- screenshot: Service Bus DLQ message peek of the poison fixture -->

<!-- screenshot: App Insights KQL trace for one correlation id -->

## Close

In production, MyAccess stays the control plane and Graph becomes the `IAccessReviewClient` implementation. In this lab, fixtures plus Slack still prove the inbox pattern: humans decide where they already live, the bus carries the work, Cosmos remembers the correlation, and managed identity is how the Azure boxes talk without a single shared key in app settings.

Local-first steps — emulators before any `az deployment` — are in the [README](README.md). Run those before you spend the Service Bus Standard dollar.
