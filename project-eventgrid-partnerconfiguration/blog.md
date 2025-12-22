# Entra → Event Grid → Azure Function (with lifecycle-safe Graph subscriptions)

## The scenario

If you’ve ever tried to keep “birthright access” tidy, you know the awkward truth: most orgs still apply access with a mix of tickets, tribal knowledge, and cleanup jobs that run… eventually.

For this post, I’m using a very normal user lifecycle story:

- A user gets created (joiner).
- A user changes attributes like department or job title (mover).
- A user is disabled or deleted (leaver).

Instead of polling directories or waiting for a ServiceNow task to land, I’m going to **listen for Microsoft Graph change events on `users`**. When something meaningful happens, I want an **Azure Function** to wake up and apply the right “birthrights” (and later, cleanup) automatically.

In the demo version, I’m intentionally starting small:

- **Trigger**: Graph change notification on `users` (delivered via Event Grid partner topic).
- **Decision**: a simple policy file decides whether we’re in detect-only mode or allowed to remediate.
- **Action**: “birthright” steps can be added behind allowlists (and anything destructive stays stubbed until I’m ready).

The rest of this post is the practical, repeatable way I got from “blank resource group” to “events flowing” without the demo quietly breaking the next day.

I hadn’t opened this repo in a few days, so I rebuilt the demo from the ground up the way I’d expect a reader to do it: **from “empty resource group” to “events flowing and deduped”**.

The story I wanted to tell in this post is simple:

- **Identity changes are events**.
- Event-driven governance is just “route → decide → act”, but with guardrails.
- And if you’re going to wire Microsoft Graph subscriptions into a demo, you need to handle **lifecycle** and **replays** like it’s production.

---

## The architecture (the mental model)

Imagine a conveyor belt:

1. **Microsoft Entra / Microsoft Graph** emits change notifications (in this demo we’ll use `users`).
2. Those notifications are delivered to **Azure Event Grid** using the “partner topic” mechanism.
3. An **Azure Function (PowerShell)** receives the events.
4. The function does three things before it ever “acts”:
   - **Dedupes** (at-least-once delivery is normal)
   - **Handles subscription lifecycle notifications** (reauthorize + renew)
   - **Applies policy** (detect-only vs remediate)

Two design choices I like here:

- **Graph calls are done via the Function’s system-assigned managed identity** (no client secret in the Function App).
- **Dedupe keys are stored in Azure Table Storage using Entra ID auth** (no storage account keys in code for dedupe).

---

## What you’ll build (end-to-end demo)

By the end, you’ll have:

- A resource group with a partner configuration, a Windows Function App, and a storage account + table.
- A Graph subscription that delivers to an Event Grid partner topic.
- An activated partner topic.
- An Event Grid subscription that routes partner topic events to the Function.
- Logs showing:
  - events arriving
  - duplicates being skipped
  - lifecycle notifications being handled

---

## Before you start (one-time prerequisites)

You’ll need:

- PowerShell 7.4+
- Azure CLI (`az`) authenticated (`az login`)
- Permissions to deploy resources into an Azure subscription

For the Graph subscription bootstrap step (creating the `users` subscription), you also need an **app registration** with permission to create subscriptions. In a dev tenant, the easiest is to use an app with Graph application permissions suitable for subscription creation (org policies vary; see your tenant’s requirements).

Placeholders used below:

- `<sub>`: Azure subscription ID
- `<rg>`: resource group name
- `<location>`: Azure region (for example `westeurope`)
- `<tenant>`: tenant ID
- `<bootstrapAppId>` / `<bootstrapSecret>`: app registration used only to create the Graph subscription
- `<partnerTopic>`: partner topic name (you choose)

---

## Step 1 — Deploy the infrastructure (partner config + Function + storage)

This repo has a real deployment script now:

```powershell
pwsh ./scripts/Deploy-Infrastructure.ps1 \
  -SubscriptionId <sub> \
  -ResourceGroupName <rg> \
  -Location <location>
```

What to capture for the blog (screenshots):

- Azure Portal → Resource group → **Deployment succeeded** (deployment outputs visible)
- Azure Portal → Function App → Identity → **System assigned: On**

What to note in the text:

- The Bicep template also creates the Azure Table used for dedupe (default table name: `DedupeKeys`).
- The Function’s managed identity is granted **Storage Table Data Contributor** on the storage account (data-plane RBAC).

---

## Step 2 — Deploy the Function code

Next, push the function code up (zip deploy):

```powershell
pwsh ./scripts/Deploy-FunctionCode.ps1 \
  -SubscriptionId <sub> \
  -ResourceGroupName <rg> \
  -FunctionAppName <functionAppNameFromStep1>
```

What to capture:

- The script output object (status/id/active)
- Azure Portal → Function App → Functions → confirm the function exists: `GovernanceEventHandler`

---

## Step 3 — Give the Function permission to manage Graph subscription lifecycle

The Function handles lifecycle events by calling:

- `POST https://graph.microsoft.com/beta/subscriptions/{id}/reauthorize`
- `PATCH https://graph.microsoft.com/v1.0/subscriptions/{id}` (extend expiration)

So it needs Graph application permission to manage subscriptions.

Grant it to the Function’s managed identity:

```powershell
pwsh ./scripts/Grant-GraphAppRolesToManagedIdentity.ps1 \
  -SubscriptionId <sub> \
  -ResourceGroupName <rg> \
  -FunctionAppName <functionAppNameFromStep1> \
  -AppRoles Subscriptions.ReadWrite.All
```

What to capture:

- Output showing the app role assignment created
- Azure Portal → Enterprise applications → your managed identity → Permissions (if you want a visual)

Important note for readers:

- You may need an admin role to grant tenant-wide Graph application permissions.

---

## Step 4 — Create the Graph subscription (delivery via Event Grid)

This is the “magic” step: we create a Graph subscription where both `notificationUrl` and `lifecycleNotificationUrl` use the Event Grid partner endpoint scheme.

```powershell
pwsh ./scripts/New-GraphUsersSubscriptionToEventGrid.ps1 \
  -TenantId <tenant> \
  -ClientId <bootstrapAppId> \
  -ClientSecret <bootstrapSecret> \
  -AzureSubscriptionId <sub> \
  -ResourceGroupName <rg> \
  -PartnerTopicName <partnerTopic> \
  -Location <location>
```

Save the output values:

- `subscriptionId`
- `clientState`

What to capture:

- The script output (especially `subscriptionId`, `expirationDateTime`, and `notificationUrl`)

---

## Step 5 — Activate the partner topic (yes, it matters)

In this flow, the partner topic has to be activated before events actually move.

```powershell
pwsh ./scripts/Activate-EventGridPartnerTopic.ps1 \
  -AzureSubscriptionId <sub> \
  -ResourceGroupName <rg> \
  -PartnerTopicName <partnerTopic>
```

What to capture:

- The activation output showing `activationState = Activated`

---

## Step 6 — Route partner topic events to the Function

The infrastructure template can create the Event Grid event subscription (partner topic → function), but it only does so if `partnerTopicName` is set in the parameters file.

Edit `infra/parameters.dev.bicepparam`:

- set `partnerTopicName = '<partnerTopic>'`

Then re-run the infra deployment:

```powershell
pwsh ./scripts/Deploy-Infrastructure.ps1 \
  -SubscriptionId <sub> \
  -ResourceGroupName <rg> \
  -Location <location>
```

What to capture:

- Azure Portal → Event Grid partner topic → Event subscriptions → the subscription pointing at your Function

---

## Step 7 — Lock down lifecycle notifications with clientState

The function validates lifecycle notifications using `GRAPH_CLIENT_STATE`.

Set it to the `clientState` returned when you created the subscription:

```bash
az functionapp config appsettings set \
  -g <rg> \
  -n <functionAppNameFromStep1> \
  --settings GRAPH_CLIENT_STATE=<clientState>
```

What to capture:

- A screenshot of the Function App app settings showing `GRAPH_CLIENT_STATE` present (value redacted)

---

## Step 8 — Prove it works: events, dedupe, and lifecycle

At this point, I like to open a log tail in one terminal:

```bash
az functionapp log tail -g <rg> -n <functionAppNameFromStep1>
```

Then trigger a user update in Entra (anything harmless—e.g., change a test user’s display name).

What you should see in logs (copy/paste snippets into the blog):

1. The “received event” log shape:

- `message`: `Received Event Grid event`
- `eventType`, `subject`, `eventId`, `eventTime`
- `dedupeKey`
- `duplicate`: `false`

2. Trigger the _same_ change again (or replay the event) and confirm dedupe kicks in:

- `message`: `Duplicate event detected; skipping processing`
- `duplicate`: `true`

3. (Optional but great for a demo) Force/observe lifecycle handling:

- `message`: `Received Graph lifecycle event`
- `lifecycleEvent`: typically `microsoft.graph.subscriptionReauthorizationRequired`
- Followed by:
  - `message`: `Graph subscription reauthorized`
  - `message`: `Graph subscription renewed`

---

## Bonus: App Insights query (KQL) for the “money” logs

If you’d rather take screenshots from **Application Insights → Logs** (instead of racing `log tail`), this query pulls out the dedupe + lifecycle entries.

> Tip: change `ago(24h)` to whatever window you need for the demo.

```kusto
traces
| where timestamp > ago(24h)
// PowerShell Functions often serialize Write-Information objects in different ways.
// This query handles both:
// - plain text in `message`
// - JSON in `message`
// - JSON/text in `customDimensions` (host-dependent)
| extend cd = todynamic(customDimensions)
| extend rawMsg = tostring(message)
| extend cdMsg = tostring(cd.Message)
| extend candidate = iif(isnotempty(cdMsg), cdMsg, rawMsg)
| extend parsed = try_parse_json(candidate)
| extend eventMessage = coalesce(tostring(parsed.message), candidate)
| where eventMessage in (
  'Received Event Grid event',
  'Duplicate event detected; skipping processing',
  'Received Graph lifecycle event',
  'Graph subscription reauthorized',
  'Graph subscription renewed'
)
| project
    timestamp,
    severityLevel,
    eventMessage,
    duplicate = tostring(parsed.duplicate),
    dedupeKey = tostring(parsed.dedupeKey),
    eventType = tostring(parsed.eventType),
    subject = tostring(parsed.subject),
    subscriptionId = tostring(parsed.subscriptionId),
    lifecycleEvent = tostring(parsed.lifecycleEvent),
    operation = tostring(parsed.operation)
| order by timestamp desc
```

---

## A quick note on “production-ish” details (even in a demo)

I intentionally treated two things as non-negotiable, even for a blog demo:

- **At-least-once delivery**: Event Grid will deliver more than once. The function stores a hash of a stable key in Table Storage and treats HTTP 409 as “already processed.”
- **Subscription lifecycle**: Graph subscriptions expire and sometimes require reauth. The handler includes the reauthorize + renew path so the demo doesn’t die after a day.

---

## What’s still a stub (and that’s OK)

Right now, the policy/remediation section is intentionally conservative:

- You can run in detect-only mode.
- The scaffolding logs a matched rule, but the “mutating Graph actions” are not implemented yet.

That’s a feature, not a bug, for a blog: it keeps the blast radius low while you demonstrate the architecture.

If you want the next incremental upgrade for the post, the cleanest one is:

- “On user disabled → revoke sessions + remove from allowlisted high-risk groups”

---

## Appendix: the scripts you’ll actually run

This is the short list I personally use when rebuilding the demo:

- `./scripts/Deploy-Infrastructure.ps1`
- `./scripts/Deploy-FunctionCode.ps1`
- `./scripts/Grant-GraphAppRolesToManagedIdentity.ps1`
- `./scripts/New-GraphUsersSubscriptionToEventGrid.ps1`
- `./scripts/Activate-EventGridPartnerTopic.ps1`
