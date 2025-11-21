# CI/CD Troubleshooting Guide

## Error: "Authentication needed. Please call Connect-MgGraph"

**Symptom:**
```
Exception: Failed to retrieve applications: Authentication needed. Please call Connect-MgGraph.
```

**Cause:**
The service principal used by GitHub Actions successfully authenticated to Azure, but it lacks the required Microsoft Graph **application permissions** in Entra ID.

**Critical Distinction:**
- **Delegated permissions** (used for interactive/local runs): User consents on behalf of themselves
- **Application permissions** (required for CI/CD): Service principal has permissions granted directly, no user context

When `azure/login@v1` sets environment variables, `Connect-WiGraph` uses application authentication mode. The scopes passed to the script are **ignored** in this mode—the service principal must already have permissions granted.

## Solution Steps

### 1. Navigate to Entra ID Portal
1. Go to [Entra ID Portal](https://entra.microsoft.com)
2. Navigate to **Identity** > **Applications** > **App registrations**
3. Find your CI/CD service principal (client ID: `${{ secrets.AZURE_CLIENT_ID }}`)

### 2. Grant Required API Permissions
1. Click on **API permissions** in the left menu
2. Click **Add a permission**
3. Select **Microsoft Graph**
4. Select **Application permissions** (NOT Delegated permissions)
5. Add the following permissions:
   - `Application.Read.All`
   - `Directory.Read.All`
   - `Policy.Read.All`
   - `IdentityRiskyServicePrincipal.Read.All` (for risky workload identity detection)

### 3. Grant Admin Consent
**CRITICAL:** After adding permissions, you must click **Grant admin consent for [Your Tenant]**

Application permissions require admin consent—they will not work until this step is completed.

### 4. Verify Permissions
1. In the **API permissions** page, check the **Status** column
2. All permissions should show "Granted for [Your Tenant]" with a green checkmark
3. Verify **Type** shows "Application" not "Delegated"

### 5. Optional: Add Remediation Permissions
If you plan to use remediation cmdlets in CI/CD (creating federated credentials, marking risky SPs as compromised):

Additional Application permissions needed:
- `Application.ReadWrite.All` (for `New-WiFederatedCredential`, `Add-WiApplicationCertificateCredential`)
- `IdentityRiskyServicePrincipal.ReadWrite.All` (for `Set-WiRiskyServicePrincipalCompromised`)

Plus assign the service principal to the **Security Administrator** directory role for risk actions.

## Validation

After granting permissions, re-run your GitHub Actions workflow. You should see:

```
Connected to Graph using EnvironmentCredential mode 'WorkloadIdentity' for tenant <tenant-id>.
Collecting credential inventory...
```

If the error persists:
1. Wait 5-10 minutes for permission propagation
2. Check that you clicked "Grant admin consent" not just "Add permission"
3. Verify the service principal isn't disabled in Entra ID
4. Confirm the federated credential subject claim matches your GitHub repo (see [Setup Federated Credential](#setup-federated-credential) below)
5. Run the workflow with `ACTIONS_STEP_DEBUG: true` to surface verbose messages (set in repo settings or add an `env:` block). You should see either `Connected to Graph using EnvironmentCredential mode` or `Connected using Azure CLI acquired Graph access token.`

### Fallback Path (Azure CLI Token)

If environment variable credential detection fails (no `AZURE_FEDERATED_TOKEN_FILE` present) but the workflow is running in GitHub Actions (`GITHUB_ACTIONS=true`), `Connect-WiGraph` attempts a fallback:

1. Calls: `az account get-access-token --resource https://graph.microsoft.com/ --tenant <tenant>`
2. Passes the resulting access token to `Connect-MgGraph -AccessToken`
3. If that fails, it finally attempts delegated scopes (expected to fail headless) and surfaces the original authentication error.

Ensure the Azure CLI is installed (it is after `azure/login`) and the service principal has the required Graph application permissions. The Azure CLI token respects those permissions.

## Setup Federated Credential (First-Time Setup)

If you haven't configured the federated credential yet:

### 1. In Entra ID Portal
1. Navigate to your app registration
2. Go to **Certificates & secrets**
3. Click **Federated credentials** tab
4. Click **Add credential**

### 2. Configure Credential
- **Federated credential scenario:** GitHub Actions deploying Azure resources
- **Organization:** Your GitHub username/org (e.g., `broberts23`)
- **Repository:** Your repo name (e.g., `vsCode`)
- **Entity type:** Choose based on trigger:
  - **Branch** for `main` branch (recommended): `ref:refs/heads/main`
  - **Environment** for GitHub Environments
  - **Pull request** for PR triggers
- **Name:** `github-actions-workload-scan` (or similar)

### 3. GitHub Repository Secrets
Add these secrets to your GitHub repository (Settings > Secrets and variables > Actions):

| Secret Name | Value |
|-------------|-------|
| `AZURE_CLIENT_ID` | Application (client) ID from Entra ID app registration |
| `AZURE_TENANT_ID` | Your Entra ID tenant ID (GUID) |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID (required by `azure/login@v1`) |

## References

- [Connect-MgGraph EnvironmentVariable](https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0#-environmentvariable)
- [Azure Identity environment variables](https://learn.microsoft.com/dotnet/api/overview/azure/identity-readme?view=azure-dotnet#environment-variables)
- [GitHub OIDC with Azure](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure)
- [Microsoft Graph application permissions](https://learn.microsoft.com/graph/permissions-reference)
