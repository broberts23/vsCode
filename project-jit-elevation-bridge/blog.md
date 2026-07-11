# Beyond Human JIT: Serverless, Passwordless Just-In-Time Privilege Elevation for Windows Server 2025 dMSAs

We’ve all been there: a critical production incident occurs, and your platform engineering team springs into action. They log in, request temporary credentials through your Just-In-Time (JIT) access portal, pass a multi-factor authentication challenge, and get to work. Their access is tracked, logged, and automatically revoked sixty minutes later.

This is the gold standard of modern security: Zero Standing Privilege (ZSP).

Yet, while we spend thousands of hours and massive budgets locking down human access, we routinely ignore a far larger attack surface: our machine identities.

Across corporate networks, high-privilege legacy service accounts run background tasks, automated deployments, and system integrations with permanent, 24/7 domain administrator rights. If an attacker compromises a server hosting one of these accounts, they don't need to bypass your complex human MFA policies—they simply harvest the service account credentials from memory and run rampant across your domain.

With the release of Windows Server 2025, Microsoft introduced delegated Managed Service Accounts (dMSAs) to solve the credential theft problem. But dMSAs only solve half of the equation. They stop attackers from stealing credentials, but they don't stop attackers from abusing permanent, over-privileged access if the application server itself is compromised.

Today, we are going to bridge that final gap. We’ll look at how to build a modern, hybrid JIT bridge using an Azure Python Function App and an Azure Arc-enabled control plane to grant and revoke high-privilege access dynamically for Windows Server 2025 dMSAs, utilizing Azure Table Storage to manage state securely and cost-effectively in the cloud.

## The Architecture: Why Cloud-to-Edge Must Be Passwordless

Historically, orchestrating changes inside an on-premises Active Directory domain from a cloud service required opening dangerous inbound firewall ports, setting up complex WinRM listeners, or storing high-value Domain Admin credentials in cleartext within cloud configuration files.

We wanted to bypass these legacy constraints entirely. Our design hinges on three zero-trust pillars:

Zero Inbound Ports: The domain controller does not listen to the public internet. Instead, it maintains a secure, outbound-only HTTPS connection (Port 443) to the Azure control plane using the Azure Connected Machine Agent (Azure Arc).

Zero Standing Cloud Secrets: The Azure Function App stores no Active Directory passwords. It authenticates to Azure Resource Manager using its own System-Assigned Managed Identity.

Stateful Serverless Scheduling: Rather than keeping an expensive serverless execution thread open or relying on memory that can be lost during an app restart, we write state to a lightweight, highly audit-compliant Azure Table Storage instance.

```text
[ Incoming API Request ]
         │
         ▼
 ┌───────────────┐
 │ Azure Function│───(1. Instantly Elevate via Arc)───► [ On-Premises Windows Server 2025 ]
 │  (HTTP POST)  │───(2. Save State with Expiry)──────┐
 └───────────────┘                                    │
                                                      ▼
                                           ┌──────────────────────┐
                                           │ Azure Table Storage  │
                                           │  (Active JIT State)  │
                                           └──────────────────────┘
                                                      ▲
                                                      │ (Query expired records every 5 mins)
 ┌───────────────┐                                    │
 │ Timer Trigger │────────────────────────────────────┘
 │ (Sweep-Revoke)│───(3. Execute Revocation via Arc)──► [ On-Premises Windows Server 2025 ]
 └───────────────┘
```

## Deconstructing the Workflow: From Request to Automatic Revocation

Let's break down exactly how this serverless bridge coordinates a 60-minute JIT lifecycle for an automated deployment engine running on our Windows Server 2025 instance.

### Step 1: The Secure Request

Our CI/CD pipeline or an IT Service Management tool (like ServiceNow) initiates a release. Before launching the deployment runner, it issues a secure POST request to our Azure Function App's elevation endpoint:

```json
{
  "dmsa_name": "dmsa_deploy_prod",
  "target_group": "JIT_AppAdmins"
}
```

### Step 2: Instant Elevation & State Capture

When the HTTP-triggered function runs, it performs two critical tasks:

First, it uses the Azure Arc RunCommand API to securely fire a minimal PowerShell snippet down to the on-premises Domain Controller. Because the Arc agent runs under the local SYSTEM context, it natively inherits the rights necessary to modify group memberships without passing an administrative password:

Add-ADGroupMember -Identity 'JIT_AppAdmins' -Members 'dmsa_deploy_prod$'

Second, rather than attempting to pause the function execution for an hour (which would timeout and trigger exorbitant serverless execution fees), the function writes a tracking record directly to Azure Table Storage:

{
  "PartitionKey": "JitActiveList",
  "RowKey": "dmsa_deploy_prod_JIT_AppAdmins",
  "dmsa_name": "dmsa_deploy_prod",
  "target_group": "JIT_AppAdmins",
  "granted_at": "2026-07-11T14:51:00Z",
  "expire_at": "2026-07-11T15:51:00Z"
}

Once the state is successfully written to Table Storage, the HTTP function instantly terminates, returning a clean 200 OK response to the caller. The deployment engine can now run its high-privilege tasks under the dMSA context.

### Step 3: The Automated Sweep & Cleanup

To enforce our 60-minute JIT limit, a secondary function inside our App runs on a regular 5-minute timer interval. This trigger is designed to be lightweight and stateless.

When it wakes up, it queries the JitElevations table, filtering for any entries where the expire_at timestamp is less than or equal to the current UTC time.

For every expired record discovered during the sweep:

It executes the revocation PowerShell script via the Azure Arc control plane:

```powershell
Remove-ADGroupMember -Identity 'JIT_AppAdmins' -Members 'dmsa_deploy_prod$' -Confirm:$false
```

Upon successful execution on the Domain Controller, it deletes the tracking entry from Azure Table Storage.

Why This Table-State Approach Wins in Production

If you have ever built scheduling engines in a serverless environment, you know that handling failures gracefully is the hardest part. If we had used an in-memory timer or a raw queue message, a brief network blip or an Active Directory lock during the exact millisecond of revocation could orphan the service account, leaving it with permanent, high-privileged access.

By utilizing Azure Table Storage as our single source of truth, we build a highly resilient architecture. If the Azure Arc control plane or the Domain Controller experiences a transient error, the entry is not deleted from Table Storage. The timer trigger will simply find the expired record again on its next sweep five minutes later and retry the revocation.

Furthermore, this table serves as an excellent, tamper-resistant audit trail. Security compliance officers can query Table Storage at any time to verify who holds active JIT elevations and trace historical access grants back to specific execution IDs.

## Moving Beyond Human JIT

By pairing the structural identity upgrades of Windows Server 2025 dMSAs with modern cloud-to-edge management tools like Azure Arc, we can bring the principles of Zero Standing Privilege to automation.

Your service accounts no longer need to be highly privileged security liabilities. They can live their daily lives in a completely harmless, unprivileged state—gaining administrative power only when called upon, and losing it the second the job is done.
