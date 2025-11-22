# Workload Identity Risk and Remediation with Microsoft Graph & PowerShell

## Introduction

Here's a problem you might not be tracking as closely as you should: every workload identity in your Entra ID tenant—the service principals and app registrations powering your automation, CI/CD pipelines, and third-party integrations—is a potential security incident waiting to happen.

I'm not talking about user accounts. Those get MFA, Conditional Access policies, password expiry rules, and constant security team scrutiny. But workload identities? They tend to live in the shadows. Someone creates an app registration, generates a client secret, drops it into a GitHub secret or Azure Key Vault, and... that's it. No rotation schedule. No expiry monitoring. No privilege reviews. That secret could have been exfiltrated months ago and you'd never know until it's used to ransomware your tenant.

The wake-up call for most organizations comes from one of three places: an Entra ID Protection alert flagging a risky service principal (yes, that's a thing now), a penetration test report showing credential sprawl, or an audit finding that half your apps have `Directory.ReadWrite.All` when they only needed `User.Read`. By then you're playing catch-up.

This article walks through a practical solution I built to get ahead of that problem: a PowerShell 7.4 toolkit that discovers, triages, and remediates workload identity risk using Microsoft Graph. The philosophy is simple—stop rotating secrets and start eliminating them. Use federated credentials (OIDC workload identity) wherever possible, short-lived certificates where federation isn't an option, and actually monitor what your workload identities are doing.

If you're following Microsoft's guidance on [protecting identities and secrets](https://learn.microsoft.com/entra/fundamentals/configure-security#protect-identities-and-secrets), this toolkit gives you the automation to make it real.

## Prerequisites

**Licensing requirements:** The toolkit's discovery features work with any Entra ID tenant and require no additional licenses—the read-only scan operations use standard Microsoft Graph permissions available to all organizations. However, several of the scenarios and enforcement capabilities discussed in this article require premium licensing:

- **Microsoft Entra ID P2 or Microsoft Entra ID Governance** — Required to access Identity Protection risk detections for workload identities (the `risky-service-principals.json` and `risky-service-principal-triage.json` artifacts). Basic risk visibility (limited reporting details) is available without premium licenses, but full risk details and risk-based actions require a premium subscription.

- **Microsoft Entra Workload Identities Premium** — Required to create or modify Conditional Access policies scoped to service principals, to use risk-based Conditional Access conditions for workload identities, and to conduct access reviews of service principals in Privileged Identity Management. You can view, start a trial, and acquire licenses at https://portal.azure.com/#view/Microsoft_Azure_ManagedServiceIdentity/WorkloadIdentitiesBlade.

- **Access Reviews for service principals** — Requires both Workload Identities Premium and an ID Governance or ID P2 license.

The core scanning and reporting functionality—credential inventory, privileged role enumeration, high-privilege app permissions, and consent settings—operates without premium licenses. You can run the full scan, generate all artifacts, and build remediation plans using the free tier. Premium licensing becomes necessary when you move from visibility to enforcement (Conditional Access) or governance automation (PIM access reviews, advanced Identity Protection actions).

For more information, see:

- Microsoft Entra Workload ID licensing: https://www.microsoft.com/security/business/identity-access/microsoft-entra-workload-identities
- Microsoft Entra ID Governance licensing: https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals
- Conditional Access for workload identities: https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity

## What This Toolkit Does

The `WorkloadIdentityTools` module is designed to answer a few critical questions about your Entra ID workload identities:

**Which secrets are ticking time bombs?** It inventories every credential across your app registrations—client secrets, certificates, federated credentials—and flags the ones that are long-lived (over 180 days) or nearing expiry (under 30 days). You get a risk score for each app so you can prioritize what to fix first.

**Who has the keys to the kingdom?** It enumerates which service principals hold privileged directory roles or dangerous Microsoft Graph permissions like `Directory.ReadWrite.All` or `Application.ReadWrite.All`. If you've got a CI/CD pipeline with Global Administrator, you'll know about it.

**What's your consent posture?** It pulls your tenant's authorization policy settings to show whether users can consent to apps, whether admin consent workflows are enabled, and who's allowed to create new app registrations. These are the knobs that control how workload identities proliferate in your environment.

**Are any of your service principals already flagged as risky?** Entra ID Protection now tracks risky workload identities (currently in beta). The toolkit pulls those signals and generates a triage report showing which service principals are at risk, confirmed compromised, or dismissed.

**How do I actually fix this?** It includes remediation helpers to create federated credentials (the secretless pattern for GitHub Actions, Azure workload identity federation, etc.) and rotate to short-lived certificates when federation isn't possible.

All of this data gets written to machine-readable JSON and CSV artifacts, so you can feed it into dashboards, SIEM systems, or just open it in Excel and start making a plan. The centerpiece is `Scan-And-Report.ps1`, a one-shot script that runs the full discovery sweep and drops everything into an `./out/` folder.

## How the Repository is Organized

The project follows a standard PowerShell module layout. Everything lives under `project-workload-identity/`: the `scripts/` folder has the standalone scan script and dependency installer, `src/WorkloadIdentityTools/` contains the module itself (manifest, loader, public cmdlets, private helpers), and `tests/Unit/` has Pester tests to validate the module loads correctly and the risk scoring logic works as expected. The `README.md` is your quick-start guide if you just want to run a scan; this blog post is the deep dive explaining why it exists and how it works under the hood.

## When You'd Use This

Let's say you're a security engineer at a company that's been using Entra ID (formerly Azure AD) for a few years. You've got hundreds of app registrations scattered across dev, staging, and production. Some were created by developers who've since left. Some were generated by automated deployment scripts. A few are still using client secrets that were pasted into wikis during hackathons.

**Scenario 1: The credential audit nobody wants to do manually.** Your CISO wants a report on every long-lived secret in the tenant. You could click through the portal for hours, or you could run `Scan-And-Report.ps1` and get a CSV with every credential, its age, and a risk score. Now you've got actionable data to build a migration roadmap.

**Scenario 2: Identity Protection started alerting on a risky service principal.** You're used to handling risky users, but this is new. What does a risky service principal even mean? Run the toolkit's risky workload identity triage and you'll see which apps are flagged, their risk levels, and recommendations for whether to confirm them as compromised or investigate further.

**Scenario 3: You're migrating from secrets to workload identity federation.** GitHub Actions just added OIDC support, and you want to stop storing `AZURE_CLIENT_SECRET` in every repository. Use the toolkit to inventory which apps are still using secrets, create federated credentials for the GitHub issuer, and track adoption over time by rerunning scans.

**Scenario 4: The compliance team needs evidence.** Auditors want proof that you're monitoring privileged app permissions and consent policies. The JSON artifacts the toolkit generates are timestamped, machine-readable compliance evidence. Drop them in an S3 bucket or Azure Storage container and you've got an audit trail.

**Scenario 5: You want this in CI/CD.** Run the scan nightly as a GitHub Actions workflow, publish the results as job summary markdown, and upload artifacts. If a new high-risk app appears, you'll see it in the workflow run without having to remember to check manually.

## Why Not Just Rotate Secrets Faster?

I know what you're thinking: "We already have a secret rotation platform. Why not just rotate secrets every 90 days and call it done?"

Because rotation is a band-aid. It assumes the secret is the inevitable part of the design and tries to minimize exposure windows. But here's the thing—secrets don't have to exist at all.

**Federated credentials** (OIDC workload identity) and **managed identities** eliminate static secrets completely. Instead of storing a password-equivalent that could leak, you configure trust relationships. GitHub Actions proves it's running in your repository by presenting a signed OIDC token; Entra ID validates the token and issues a short-lived access token. No secret ever hits your CI/CD environment.

The advantages are huge:

- **No exfiltration risk.** There's nothing static to steal. An attacker would have to compromise the OIDC issuer itself (GitHub, Azure, AWS) which is significantly harder than grabbing a secret from a Key Vault or environment variable.
- **No rotation schedules.** Tokens are issued on-demand and expire in minutes or hours. You never have to coordinate "rotate this secret across 12 environments by Friday."
- **Faster incident response.** If a workload identity is compromised, you revoke the trust relationship in Entra ID. You don't have to hunt down every place a secret was copied.
- **Better CI ergonomics.** Developers don't need to know about secrets at all. They just configure the OIDC subject claim and it works.
- **Policy enforcement at the identity layer.** Conditional Access policies can apply to service principals. You can require MFA step-up, device compliance, or network restrictions without touching secret storage.

Where federation isn't an option—legacy systems, third-party integrations that don't support OIDC—short-lived certificates are the next best thing. A cert with a 30-day lifetime that auto-rotates is orders of magnitude safer than a 2-year client secret that someone pasted into Slack.

This toolkit exists to accelerate that transition: discover where secrets still exist, generate migration recommendations, and provide helpers to create federated credentials or rotate to short-lived certs. The goal isn't "rotate faster"; it's "remove the secret."

**Layer adaptive controls:** Once high-risk apps are identified, enforce Conditional Access for workload identities (requires Workload Identities Premium licensing) to block risky service principals based on location or risk signals. Pair this with Continuous Access Evaluation (CAE) so revocations—service principal disable, deletion, or risk escalation—take effect immediately without waiting for token expiry. Validate outcomes via the Service Principal sign-in logs to confirm that enforcement is working as expected. The toolkit's `risky-service-principals.json` and `privileged-roles.json` artifacts provide the candidate list for scoping these policies.

## How It Works Under the Hood

The module is built on PowerShell 7.4 with strict mode, `[CmdletBinding()]` attributes, and proper parameter validation. It's designed to be testable (Pester tests with mocks) and pipeable (objects, not formatted text).

**The Microsoft Graph PowerShell SDK** is the engine. The v1.0 cmdlets handle apps, authorization policies, and role enumeration. For risky workload identities—which are currently in preview—it uses the beta endpoints. That means you need the `Microsoft.Graph.Beta.*` modules for some operations, and those APIs could change before they go GA. The toolkit makes that boundary explicit: cmdlets that touch beta data have `Beta` in the name (like `Get-WiBetaRiskyServicePrincipal`), and the documentation warns you upfront.

**Authentication is context-aware.** The `Connect-WiGraph` wrapper handles two modes: interactive delegated scopes for local runs (you authenticate as yourself and get prompted for consent), and automatic environment variable detection for CI/CD. When the toolkit sees `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE` in the environment (which `azure/login` in GitHub Actions sets), it switches to `Connect-MgGraph -EnvironmentVariable` and authenticates as the pipeline's service principal with no interaction required. Local runs are unaffected—you just pass scopes like normal.

**Discovery is read-only by default.** When you run `Scan-And-Report.ps1`, it calls a series of cmdlets that enumerate applications, credentials, role assignments, app permissions, consent settings, and risky service principals. All of this uses the minimum Graph scopes required: `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `IdentityRiskyServicePrincipal.Read.All`. Nothing gets modified unless you explicitly invoke a remediation cmdlet.

**Remediation cmdlets require higher privileges and support `-WhatIf`.** Creating a federated credential needs `Application.ReadWrite.All`. Confirming a service principal as compromised needs `IdentityRiskyServicePrincipal.ReadWrite.All` and the Security Administrator role. Both scenarios use approved verbs (`New-WiFederatedCredential`, `Set-WiRiskyServicePrincipalCompromised`) with `SupportsShouldProcess`, so you can test with `-WhatIf` before committing changes.

**Everything outputs structured data.** The scan script writes JSON and CSV files to `./out/`. Each artifact is timestamped and includes metadata like the tenant ID and when the scan ran. You can parse these with `ConvertFrom-Json`, load them into pandas, or push them to Azure Monitor Logs. There's no proprietary format—just standards.

**Future enhancement:** Optional CAE token capability detection and recommendation flags (proposed column `SupportsCae` in the credential inventory) would enable prioritization of workloads for real-time enforcement. Applications that send the `xms_cc=cp1` claim in their token requests receive CAE-enabled long-lived tokens (24 hours) subject to instant revocation events—a powerful upgrade over traditional 1-hour token lifetimes.

## The Discovery Side

The heavy lifting happens in a handful of cmdlets that map directly to Microsoft Graph queries:

**`Get-WiApplicationCredentialInventory`** pulls every app registration in the tenant and iterates over its `passwordCredentials`, `keyCredentials`, and `federatedIdentityCredentials`. For each credential, it calculates how long it's been active and how long until it expires. Long-lived (>180 days) or near-expiry (<30 days) credentials get flagged with a risk score. The output includes recommendations: "migrate to federated credential" for secrets, "shorten lifetime" for long-lived certs.

**`Get-WiServicePrincipalPrivilegedAssignments`** enumerates service principals with directory role assignments. It calls `Get-MgDirectoryRole` to list all roles, then fetches their members and filters for service principals. If you've got a CI pipeline with Global Administrator or an integration app with Privileged Role Administrator, it shows up here.

**`Get-WiHighPrivilegeAppPermissions`** looks for applications holding dangerous Graph permissions—things like `Directory.ReadWrite.All`, `Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`. These are the permissions that let an app modify users, create new apps, or assign roles. You'd be surprised how many apps have these permissions "just in case."

**`Get-WiTenantConsentSettings`** fetches the authorization policy (`Get-MgPolicyAuthorizationPolicy`) and extracts the consent knobs: whether users can consent to apps, whether admin consent workflows are enabled, who can create apps, and whether email verification is required. This is the posture that controls how workload identities proliferate in your tenant.

**Classification & Attributes:** Beyond discovery, you can map discovered apps to custom security attributes (e.g., `RiskTier`, `RemediationPhase`, `DataSensitivity`) using Microsoft Graph PowerShell. Custom security attributes in Entra ID enable filtered views and targeted policy scope—for example, applying stricter Conditional Access policies to apps tagged with `DataSensitivity=High` or tracking migration progress with `RemediationPhase=InProgress`. While the toolkit doesn't automatically assign these attributes, the credential inventory and high-privilege permissions data provide the inputs for classification decisions. See https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/custom-security-attributes-apps for implementation guidance.

**`Get-WiBetaRiskyServicePrincipal`** and **`Get-WiBetaRiskyServicePrincipalHistory`** hit the Identity Protection beta endpoints to pull risky workload identities. These are service principals that Microsoft's risk detection systems have flagged—maybe they authenticated from an anonymous IP, or their credentials showed up in a breach, or there was anomalous sign-in behavior. The triage report (`Get-WiRiskyServicePrincipalTriageReport`) aggregates the distribution by risk level and risk state so you can see at a glance how many are at risk vs. confirmed compromised vs. dismissed.

## The Remediation Side

Once you've identified problems, the toolkit provides helpers to fix them:

**`New-WiFederatedCredential`** creates a federated identity credential on an app registration. You specify the issuer (like `https://token.actions.githubusercontent.com` for GitHub Actions), the subject (like `repo:myorg/myrepo:ref:refs/heads/main`), and optionally the audience. The credential is created immediately and you can start using OIDC tokens to authenticate. No secret required.

**`Add-WiApplicationCertificateCredential`** generates a short-lived certificate credential. By default it's valid for 90 days, but you can configure shorter lifetimes. The cmdlet returns the certificate with private key so you can store it in Key Vault or another secure location. This is the fallback for systems that can't do federation.

**`Set-WiRiskyServicePrincipalCompromised`** and **`Clear-WiRiskyServicePrincipalRisk`** are the approved-verb wrappers around the Identity Protection risk action APIs. If a service principal is flagged and you've confirmed it's compromised (maybe you found the secret in a public repo), you mark it as compromised so Microsoft's signals improve. If it's a false positive, you dismiss the risk. Both cmdlets support `-WhatIf` so you can preview the action before committing.

All of these require elevated permissions: `Application.ReadWrite.All` for credential changes, `IdentityRiskyServicePrincipal.ReadWrite.All` plus the Security Administrator role for risk actions. The module won't prompt you for consent on the fly—you need to authenticate with those scopes upfront.

**Post-remediation governance:** After addressing immediate risks, seed Privileged Identity Management (PIM) recurring access reviews from the `privileged-roles.json` and `high-privilege-app-permissions.json` artifacts. Access reviews for service principals require Workload Identities Premium plus ID Governance licensing. Generate a CSV of candidate service principals with their role assignments, last sign-in dates, and permission counts, then import that scope into PIM to establish quarterly or semi-annual entitlement hygiene reviews. This closes the loop from discovery → remediation → ongoing governance. See https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review for setup guidance.

## Running It Yourself

The quickest way to see what you're dealing with is to run the scan locally. Here's what that looks like:

First, install the Microsoft Graph PowerShell modules:

```powershell
./project-workload-identity/scripts/Install-Dependencies.ps1
```

This installs the Graph SDK and sets the PowerShell Gallery as trusted if it isn't already. You only need to do this once per machine.

Now import the module and authenticate:

```powershell
Import-Module ./project-workload-identity/src/WorkloadIdentityTools/WorkloadIdentityTools.psd1
Connect-WiGraph -TenantId 'your-tenant-id'
```

By default, `Connect-WiGraph` requests delegated scopes for discovery (Application.Read.All, Directory.Read.All, etc.). You'll get an OAuth prompt asking for consent. Approve it and you're connected.

Now run the inventory:

```powershell
$inventory = Get-WiApplicationCredentialInventory -All
$inventory | Where-Object { $_.RiskLevel -eq 'High' } | Format-Table DisplayName, CredentialType, DaysUntilExpiry, RiskReasons
```

This returns every high-risk credential in your tenant—secrets that are ancient, certificates about to expire, apps that should have migrated to federation months ago. The `RiskReasons` column tells you why it's flagged.

If you want to check risky service principals (beta), reconnect with the Identity Protection scope:

```powershell
Connect-WiGraph -Scopes @('IdentityRiskyServicePrincipal.Read.All') -TenantId 'your-tenant-id'
$triage = Get-WiRiskyServicePrincipalTriageReport
$triage.Distribution.ByRiskLevel | Format-Table
```

This shows how many service principals are at each risk level and what states they're in. If you see any confirmed compromised, those need immediate action.

For a full scan with all the artifacts, just run:

```powershell
./project-workload-identity/scripts/Scan-And-Report.ps1
```

The script connects, runs every discovery cmdlet, and writes JSON and CSV files to `./out/`. You can open those in Excel, load them into Power BI, or push them to your SIEM.

## Testing in a Dev Tenant

If you're running this in a brand-new dev tenant that doesn't have a ton of workload identities yet, the scan results might be underwhelming. You'll see a handful of app registrations, maybe none with high-risk credentials, and probably zero risky service principals because your tenant hasn't been around long enough for Identity Protection to build a baseline.

That's where the lab seeding scripts come in. Run:

```powershell
./scripts/Bootstrap-WiLab.ps1 -TenantId 'your-dev-tenant-id'
```

This creates a set of `wi-lab-*` apps and service principals that cover the interesting cases: long-lived secrets, near-expiry secrets, certificate credentials, federated-only identities, and a few with high-privilege permissions. The script is idempotent—if you run it twice, it'll reuse the existing apps and update credentials as needed.

Now rerun the scan:

```powershell
./scripts/Scan-And-Report.ps1
```

You'll see the lab identities show up in `credential-inventory.json`, `high-privilege-app-permissions.json`, and `privileged-roles.json`. This gives you realistic data to experiment with—try creating a federated credential on one of the secret-based apps, or rotate a certificate, and see how the scan results change.

When you're done, clean up:

```powershell
./scripts/Cleanup-WiLab.ps1 -TenantId 'your-dev-tenant-id'
```

This removes all the `wi-lab-*` identities. Use `-WhatIf` first if you want to preview what it's going to delete.

**Important: Do not run these scripts in production.** They're designed for non-production tenants where you can safely create and delete app registrations. The bootstrap script doesn't manipulate Identity Protection risk state directly (you can't forge risk detections anyway), so the risky service principals report will stay empty in a fresh dev tenant—and that's fine.

## Hooking It Into CI/CD

The real power comes from running this continuously. You want to catch new high-risk apps the day they're created, not during the next quarterly audit.

Here's how you set that up in GitHub Actions. First, create a service principal in Entra ID and configure a federated credential for your GitHub repo (see `New-WiFederatedCredential` or do it in the portal). Grant it the Graph application permissions it needs: `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `IdentityRiskyServicePrincipal.Read.All`. Make sure those permissions are admin-consented.

Add the service principal's client ID and your tenant ID as GitHub repository secrets:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID` (required by `azure/login`)
- `WI_SCAN_TENANT_ID` (can be the same as `AZURE_TENANT_ID`)

Now create a workflow file (`.github/workflows/workload-identity-scan.yml`) that looks like this:

```yaml
name: Workload Identity Scan
on:
  schedule:
    - cron: "0 2 * * *" # Daily at 2 AM UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v3

      - name: Azure Login (OIDC)
        uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install Dependencies
        shell: pwsh
        run: ./project-workload-identity/scripts/Install-Dependencies.ps1

      - name: Run Scan
        shell: pwsh
        env:
          WI_SCAN_TENANT_ID: ${{ secrets.WI_SCAN_TENANT_ID }}
        run: ./project-workload-identity/scripts/Scan-And-Report.ps1

      - name: Render HTML Report
        shell: pwsh
        run: ./project-workload-identity/scripts/Write-ScanReport.ps1 -OutputFolder ./out

      - name: Publish Report Summary
        shell: pwsh
        env:
          REPORT_PATH: ./out/workload-identity-report.html
        run: ./project-workload-identity/scripts/Publish-ScanReportSummary.ps1

      - name: Upload Artifacts
        uses: actions/upload-artifact@v3
        with:
          name: wi-scan-artifacts
          path: ./out/
```

The `azure/login` step sets the `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE` environment variables. When the scan script calls `Connect-WiGraph`, it detects those variables and uses `Connect-MgGraph -EnvironmentVariable` to authenticate as the service principal—no client secret required.

The workflow runs nightly, scans the tenant, generates an HTML report, publishes a summary to the GitHub Actions job summary (so you can see highlights without downloading artifacts), and uploads the full JSON/CSV artifacts for later analysis.

If a new high-risk app appears, you'll see it in the next morning's workflow run. If someone creates a service principal with Global Administrator, it shows up in `privileged-roles.json`. If Identity Protection flags a risky workload identity, it's in the triage report. All without manual intervention.

**Optionally generate `conditional-access-candidates.json`:** Extend the scan to produce a list of service principal object IDs exceeding defined risk thresholds (e.g., high-risk credentials + privileged roles, or confirmed risky status from Identity Protection). This artifact can drive out-of-band policy provisioning—import the object IDs into a Conditional Access policy scoped to block access from untrusted locations or at elevated risk levels. The candidates file becomes a living policy scope that updates nightly as new high-risk apps are discovered.

## What You Get Out

Every scan writes a set of artifacts to `./out/`. Here's what each one contains:

**`credential-inventory.json` / `.csv`** — Every credential across all app registrations: when it was created, when it expires, its type (secret/cert/federated), risk level, and recommended actions. This is your starting point for building a remediation roadmap.

**`privileged-roles.json`** — Service principals with directory role assignments. If a CI pipeline has Global Administrator or an integration app has Privileged Role Administrator, it's in here.

**`high-privilege-app-permissions.json`** — Applications holding dangerous Graph permissions like `Directory.ReadWrite.All`, `Application.ReadWrite.All`, or `RoleManagement.ReadWrite.Directory`. These are the apps that could wreak havoc if compromised.

**`consent-settings.json`** — Your tenant's authorization policy: whether users can consent to apps, whether admin consent workflows are enabled, who can create apps. This is the posture that controls how workload identities proliferate.

**`risky-service-principals.json`** — Identity Protection's list of risky workload identities (beta). Includes risk level, risk state (at risk, confirmed compromised, dismissed), and when the risk was detected.

**`risky-service-principal-triage.json`** — Aggregated summary of risky service principals: how many at each risk level, distribution by state, recommendations for action.

**`scan-summary.json`** — High-level counts: total apps, total credentials, how many are high-risk, how many are federated, etc. This is useful for dashboards or executive summaries.

**`workload-identity-report.html`** — An HTML dashboard that presents all of the above in a human-readable format. Open it in a browser and you've got a visual overview with sortable tables and color-coded risk levels.

All JSON files include metadata (tenant ID, scan timestamp) and follow a consistent schema. You can load them into Power BI, push them to Azure Monitor Logs, or just `ConvertFrom-Json` and analyze them in PowerShell.

## What This Isn't

Let's be clear about scope. This toolkit is designed to discover workload identity risks and provide remediation helpers—it's not trying to be a full-blown identity governance platform.

**It's not a SIEM pipeline.** The artifacts are JSON and CSV files you can push to your SIEM, but the toolkit itself doesn't handle log ingestion, correlation, alerting, or retention policies. You'll need to wire that up yourself.

**It's not a Conditional Access automation tool.** You can use the privileged app permission data to inform CA policy design, but the toolkit doesn't create or modify Conditional Access policies. That's a separate problem domain.

**It's not doing ML-based risk enrichment.** The risk scoring for credentials is rule-based (age > 180 days = long-lived, expiry < 30 days = near-expiry). Identity Protection's risky service principal detections come from Microsoft's ML models, but this toolkit just surfaces them—it doesn't extend or retrain the models.

**It's not bundling interactive dashboards.** The HTML report is a standalone file you can open in a browser, but it's not a live dashboard with drill-downs and refresh buttons. If you want that, load the JSON artifacts into Power BI or Grafana.

The goal is to give you the raw material—discovery data, remediation helpers, structured output—so you can build the governance workflow that fits your organization. The toolkit handles the hard part (querying Graph, scoring risk, generating artifacts); you handle the integration layer.

## Security and Governance Notes

A few things to keep in mind as you use this toolkit:

**The artifacts don't contain secrets, but they do reveal privilege posture.** The credential inventory includes metadata (credential IDs, start/end dates) but not the actual secrets or private keys. However, someone with access to these artifacts can see which apps have high-risk credentials, privileged role assignments, or dangerous permissions. Treat the output files accordingly—don't drop them in a public S3 bucket.

**Beta APIs are subject to change.** The risky workload identity endpoints are currently in preview. Microsoft could change the schema, retire properties, or move things to v1.0 with breaking changes. Always test in a non-production tenant first, and expect to update the toolkit when those APIs go GA.

**Least privilege applies to the scanner too.** The scan runs with read-only Graph permissions by default. Don't grant it `Application.ReadWrite.All` or `Directory.ReadWrite.All` unless you're actively using the remediation cmdlets. If you're running this in CI, consider using a separate service principal for discovery vs. remediation, so the nightly scan can't accidentally modify your tenant.

**Use the artifacts for compliance evidence.** The JSON files are timestamped and include the tenant ID. If you need to prove to auditors that you're monitoring workload identity risk, archive these artifacts in Azure Storage or an S3 bucket with immutability policies. Now you've got a tamper-evident audit trail.

**Integrate with access reviews.** If you're using Entra ID Governance access reviews for service principals, you can use the privileged role and high-privilege permission data from this toolkit to seed the review scope. Export the JSON, identify the high-risk apps, and kick off targeted reviews for those identities.

**Enable CAE for eligible workload identities.** Applications accessing Microsoft Graph can opt into Continuous Access Evaluation by requesting tokens with the `xms_cc=cp1` claim. This enables 24-hour long-lived tokens subject to instant revocation on disable, delete, or risk state changes. Monitor revocations in the Service Principal sign-in logs—look for the "Continuous access evaluation" field and verify that blocked sessions show appropriate failure reasons. Track an adoption metric (percentage of high-privilege principals covered by Conditional Access policies) to measure your enforcement posture over time. Note: Conditional Access for workload identities requires Workload Identities Premium licensing and applies only to single-tenant service principals (managed identities and multi-tenant apps are excluded).

## References

PowerShell / Testing:

- Pester overview: https://learn.microsoft.com/powershell/scripting/testing/overview?view=powershell-7.4

Graph SDK (v1.0):

- Connect-MgGraph: https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-1.0
- Get-MgApplication: https://learn.microsoft.com/powershell/module/microsoft.graph.applications/get-mgapplication?view=graph-powershell-1.0
- New-MgApplicationFederatedIdentityCredential: https://learn.microsoft.com/powershell/module/microsoft.graph.applications/new-mgapplicationfederatedidentitycredential?view=graph-powershell-1.0
- Add-MgApplicationKey: https://learn.microsoft.com/powershell/module/microsoft.graph.applications/add-mgapplicationkey?view=graph-powershell-1.0
- Get-MgPolicyAuthorizationPolicy: https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/get-mgpolicyauthorizationpolicy?view=graph-powershell-1.0

Graph Beta (Risky Workload Identities):

- List risky SPs: https://learn.microsoft.com/en-us/graph/api/identityprotectionroot-list-riskyserviceprincipals?view=graph-rest-beta
- Risk history: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-list-history?view=graph-rest-beta
- Confirm compromised: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-confirmcompromised?view=graph-rest-beta
- Dismiss risk: https://learn.microsoft.com/en-us/graph/api/riskyserviceprincipal-dismiss?view=graph-rest-beta

## Where to Go From Here

Workload identity risk isn't a "rotate secrets faster" problem. It's a "stop using secrets" problem. And until you get there, it's a "know what you have" problem.

This toolkit gives you visibility into the current state: which apps are using ancient secrets, which service principals have privileged access, which identities are already flagged by Identity Protection. That's the baseline. From there, you build a remediation roadmap: migrate GitHub Actions to OIDC federation, rotate long-lived certificates to short-lived ones, remove excessive Graph permissions, revoke privileged roles that aren't actively used.

The key is making this continuous. Run the scan nightly in CI/CD. Publish the results to your security team's dashboard. Alert on new high-risk apps. Track migration progress over time. When the next penetration test happens, you'll have months of audit data showing you've been actively managing workload identity risk—not just reacting to findings.

Extend the artifacts into whatever system you already use: Power BI for executive dashboards, Azure Monitor Logs for alerting, ServiceNow for ticketing, Jira for remediation tracking. The JSON schema is stable and documented; you're not locked into a proprietary format.

The end goal is a tenant where standing secrets don't exist, privileged assignments are time-bound and deliberate, and compliance evidence is generated automatically. That's achievable today with the tools Entra ID already provides—federated credentials, short-lived certificates, managed identities, Conditional Access for service principals, Identity Protection for workload identities. This project just gives you the automation to make it practical.

Start with a scan. See what you're dealing with. Build a plan. Automate the remediation. Repeat.

The blueprint is here. The rest is execution. 🚀

License: MIT
