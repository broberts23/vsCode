# Azure Container Apps Self-Hosted GitHub Runner Project

Deploy ephemeral GitHub Actions runners on Azure Container Apps jobs using infrastructure-as-code, PowerShell automation, and KEDA scale rules. This scaffold aligns with the Microsoft Learn tutorial on [Deploying self-hosted CI/CD runners and agents with Azure Container Apps jobs](https://learn.microsoft.com/en-us/azure/container-apps/tutorial-ci-cd-runners-jobs?tabs=powershell&pivots=container-apps-jobs-self-hosted-ci-cd-github-actions) and extends it with reusable assets for enterprise-ready rollouts.

## 1. Solution Overview

- **Problem space**: Provide secure, on-demand compute for workflows that require custom tooling, private networking, or access to internal systems not available to GitHub-hosted runners.
- **Solution summary**: Container Apps event-driven jobs spin up short-lived runner containers built from Azure Container Registry (ACR). KEDA evaluates GitHub queue depth and launches runners as needed, minimizing idle cost while respecting GitHub rate limits.
- **Key outcomes**:
  - Infrastructure described through Bicep templates and parameter files.
  - PowerShell 7.4 automation scripts for deployment, GitHub secret handling, and Entra federated credential wiring.
  - Operational guidance covering scaling, monitoring, and lifecycle management.

## 2. Architecture Blueprint

| Layer          | Component                                      | Notes                                                                                                                                                                                                                                      |
| -------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Identity       | User-assigned managed identity (optional)      | Authenticates Container Apps job to pull private images and call Azure APIs.                                                                                                                                                               |
| Compute        | Azure Container Apps environment & jobs        | Event-driven jobs host ephemeral GitHub Actions runners. See [Jobs in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/jobs).                                                                                  |
| Network        | Azure Virtual Network + delegated subnet & NSG | Provides private connectivity for the Container Apps environment and restricts ingress/egress per [Custom virtual networks for Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks?tabs=bicep). |
| Image Registry | Azure Container Registry                       | Stores hardened runner images; configured for ARM audience tokens for managed identity pulls.                                                                                                                                              |
| Secrets        | GitHub environment secrets + Azure Key Vault   | Environment secret seeds the GitHub App private key; deployment copies it into Key Vault for runtime retrieval by the Container Apps job and KEDA scaler authentication.                                                                   |
| Observability  | Log Analytics workspace & Azure Monitor        | Captures job execution history, container logs, and scaling metrics.                                                                                                                                                                       |
| Scaling        | KEDA GitHub runner scaler                      | Evaluates `targetWorkflowQueueLength` to add/remove executions. Refer to [KEDA GitHub runner scaler](https://keda.sh/docs/latest/scalers/github-runner/).                                                                                  |

**Lifecycle**

1. GitHub workflow targeting the `self-hosted` label queues a job.
2. KEDA scaler polls GitHub API using the GitHub App credentials replicated from the environment secret into Key Vault (PAT fallback remains available) and detects the queued workflow.
3. Container Apps job spins up a runner replica, authenticates back to GitHub, executes, then exits.
4. Logs stream to Log Analytics; jobs scale back to zero when idle (default cooldown 300 seconds per [Container Apps scaling behavior](https://learn.microsoft.com/en-us/azure/container-apps/scale-app#scale-behavior)).

## 3. Prerequisites

- **Azure**
  - Active subscription with `Microsoft.App` and `Microsoft.OperationalInsights` resource providers registered. Use [`Register-AzResourceProvider`](https://learn.microsoft.com/powershell/module/az.resources/register-azresourceprovider?view=azps-latest).
  - Permissions: `Contributor` to target resource group, `AcrPull` on ACR if using separate identity.
  - Azure CLI (for ad-hoc validation) and PowerShell 7.4 with Az modules. Install Az via [`Install-Module`](https://learn.microsoft.com/powershell/module/powershellget/install-module?view=powershell-7.4).
- **GitHub**
  - Repository (private recommended) with permission to administer self-hosted runners.
  - GitHub App registered in your organization with `Actions: Read`, `Self-hosted runners: Read/Write`, and (optionally) `Administration: Read` permissions. Store the app ID and installation ID as GitHub environment variables and keep the generated private key in an environment secret (refer to [Authenticating with a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app) and [Generating a JSON Web Token (JWT) for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)).
- **Local tooling**
  - Docker or OCI-build capable workstation to author Dockerfiles (remote ACR build reduces local dependencies).
  - Logged-in session via [`Connect-AzAccount`](https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest) and optionally [`Connect-MgGraph`](https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-beta) for federated credential automation.

## 4. Repository Structure & Artifacts

```
project-github-runner/
├─ Dockerfile.github             # Dockerfile for the GitHub Actions runner image
├─ github-actions-runner/
│  └─ entrypoint.sh              # Container entrypoint configuring the runner
├─ README.md                     # Deployment guide (this file)
├─ infra/
│  ├─ parameters.sample.json     # Template for parameter overrides
│  ├─ main.bicep                 # Composes workspace, environment, ACR, and the job
│  ├─ containerapps/             # Bicep modules (job, env, registry)
│  └─ network/
│     └─ vnet.bicep              # Virtual network, delegated subnet, and NSG for Container Apps
└─ scripts/
  ├─ ContainerApps-Deploy-Job.ps1        # Creates Container Apps job via Azure CLI
  ├─ ContainerInit.ps1                   # Optional container init hook to install modules
  ├─ Create-FederatedCredential.ps1      # Adds Entra federated credential for GitHub OIDC
  ├─ Build-GitHubRunnerImage.ps1         # Builds/pushes the Docker image defined in Dockerfile.github
  └─ Deploy-GitHubRunner.ps1             # End-to-end deployment wrapper using Bicep
```

> **Action**: Copy `infra/parameters.sample.json` to `infra/parameters.dev.json` (or similar) and adjust per environment. Keep secrets external to source control.

## 5. Manual Deployment Workflow (End-to-End)

All commands assume PowerShell 7.4 (`pwsh`) with execution from the repository root.

1.  **Install/Update Az modules**

    ```powershell
    Install-Module -Name Az -Scope CurrentUser -Force
    Update-Module -Name Az.App -ErrorAction SilentlyContinue
    ```

    Reference: [`Install-Module`](https://learn.microsoft.com/powershell/module/powershellget/install-module?view=powershell-7.4), [`Update-Module`](https://learn.microsoft.com/powershell/module/powershellget/update-module?view=powershell-7.4).

2.  **Authenticate & prepare Azure environment**

    ```powershell
    # Sign in interactively
    Connect-AzAccount

    # Ensure required providers are registered
    Register-AzResourceProvider -ProviderNamespace Microsoft.App
    Register-AzResourceProvider -ProviderNamespace Microsoft.OperationalInsights
    ```

3.  **Set environment context**

    ```powershell
    $RESOURCE_GROUP = 'rg-github-runner-dev'
    $LOCATION       = 'eastus'
    $ENVIRONMENT    = 'env-github-runner'
    $ACR_NAME       = 'ghrunnerdevacr'
    $IMAGE_NAME     = 'github-actions-runner:2.329.0'
    $JOB_NAME       = 'github-actions-runner-job'
    $REPO_OWNER     = 'your-org'
    $REPO_NAME      = 'your-repo'
    $GITHUB_REPO    = "$REPO_OWNER/$REPO_NAME"
    ```

4.  **Customize Bicep parameters**

    ```powershell
    Copy-Item -Path ./infra/parameters.sample.json -Destination ./infra/parameters.dev.json -Force
    # Edit the copy to set values (location, environment name, ACR details, secrets references, etc.)
    ```

    Bicep concepts: [Bicep overview](https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview).

5.  **Deploy infrastructure**

    ````powershell # Construct full image reference and deploy
    $FULL_IMAGE = "$ACR_NAME.azurecr.io/$IMAGE_NAME"

        ./scripts/Deploy-GitHubRunner.ps1 `
          -ResourceGroupName $RESOURCE_GROUP `
          -Location $LOCATION `
          -GitHubRepo $GITHUB_REPO `
          -TemplatePath ./infra/main.bicep `
          -TemplateParameters @{
            location                 = @{ value = $LOCATION }
            baseName                 = @{ value = 'gh-runner' }              # optional; controls resource names
            containerImage           = @{ value = $FULL_IMAGE }              # required
            acrName                  = @{ value = $ACR_NAME }
            githubAppApplicationId   = @{ value = '<github-app-id-guid>' }
            githubAppInstallationId  = @{ value = '<github-app-installation-id>' }
            githubAppPrivateKey      = @{ value = (Get-Secret -Name 'GitHubAppPrivateKey') }
            githubPatSecretValue     = @{ value = '' }                       # optional fallback PAT when App auth unavailable
            virtualNetworkAddressPrefix = @{ value = '10.10.0.0/16' }
            containerAppsSubnetPrefix  = @{ value = '10.10.0.0/23' }
            platformReservedCidr       = @{ value = '10.200.0.0/24' }
            platformReservedDnsIp      = @{ value = '10.200.0.10' }
            dockerBridgeCidr           = @{ value = '172.16.0.0/16' }
            internalEnvironment        = @{ value = $false }
            # The script infers githubOwner/githubRepo from -GitHubRepo automatically
          }
        ```

    This script:
    ````

- Ensures the resource group exists via [`New-AzResourceGroup`](https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroup?view=azps-latest).
- Deploys Bicep using [`New-AzResourceGroupDeployment`](https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest).
- When GitHub App values are present, persists the private key into Azure Key Vault and grants the Container Apps job identity `Key Vault Secrets User` so the scaler and runner can retrieve it securely.

- Optionally retrieves a GitHub runner registration token and injects it as `RUNNER_TOKEN` environment variable.
  - Adds a federated credential to the job’s managed identity using Microsoft Graph (beta) if identity outputs are available.
  - Applies virtual network defaults when `-TemplateParameters` omits them; override as needed per [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters).
- Provisions Azure Container Registry, grants the job’s managed identity `AcrPull`, and wires the registry into the Container Apps job so no manual ACR setup is required.

6. **Build and push runner image**

   - The repository includes `Dockerfile.github` and `github-actions-runner/entrypoint.sh`, which install the latest runner release (`v2.329.0`, see https://github.com/actions/runner/releases/tag/v2.329.0). Update these files if you need extra tooling.
   - Build (and optionally push) the image using the helper script after authenticating to the registry (for example, `az acr login --name $ACR_NAME`):
     `` powershell
./scripts/Build-GitHubRunnerImage.ps1 `
  -ImageTag "$ACR_NAME.azurecr.io/github-actions-runner:2.329.0" `
  -Push
 ``
     This script wraps `docker build`/`docker push`. The Bicep deployment automatically provisions the Azure Container Registry, so ensure the tag aligns with the `acrName` parameter.

7. **Provision Container Apps job (alternate)**
   If you need to regenerate the job definition on the fly or prototype outside Bicep, use `ContainerApps-Deploy-Job.ps1` to generate the equivalent Azure CLI command and optionally execute it.

8. **Configure GitHub workflow**
   In your repository, update workflow YAML to target the job labels:

   ```yaml
   runs-on: self-hosted
   labels: [azure-container-apps]
   ```

   Ensure label alignment with your job configuration.

9. **Run smoke tests**
   - Queue a workflow dispatch in GitHub to validate runner registration.
   - Monitor job status: `az containerapp job execution list --name $JOB_NAME --resource-group $RESOURCE_GROUP --output table`
   - Review logs in Log Analytics queries or via portal.

### GitHub Actions bootstrap workflow

The repository ships with `.github/workflows/bootstrap-infra.yml`, a GitHub Actions pipeline that automates the baseline deployment and container build steps described above.

- **Triggers**
  - Supports manual dispatch with inputs for `environment`, optional image tag suffix, and a parameter file override so you can bootstrap dev/stage/prod independently.
- **Execution flow**
  1. Resolves environment metadata (resource group, Azure region, ACR name, parameters file) and builds a fully qualified image tag.
  2. Authenticates to Azure with OpenID Connect via [`azure/login@v2`](https://github.com/Azure/login) using federated credentials created per [Deploy Bicep with GitHub Actions](https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-github-actions).
  3. Ensures the target resource group exists using `az group create` (see [`az group create`](https://learn.microsoft.com/cli/azure/group?view=azure-cli-latest#az-group-create)).
  4. Deploys `infra/main.bicep` through [`azure/bicep-deploy@v2`](https://github.com/Azure/bicep-deploy), passing the computed container image reference and ACR name.
  5. Logs Docker into Azure Container Registry (`az acr login`) and builds/pushes the runner image with [`docker/build-push-action@v6`](https://github.com/docker/build-push-action#usage).
  6. Publishes a run summary enumerating the resource group, image tag, and `Microsoft.App/jobs` output identifiers.
- **Required GitHub secrets and environment variables**
  - `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`: service principal values tied to your federated credential trust that power `azure/login` (see [Configure deployment credentials](https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-github-actions?tabs=CLI%2Copenid#configure-the-github-secrets)).
  - Environment-level variables `GH_APP_ID` and `GH_APP_INSTALLATION_ID` that expose the GitHub App metadata to the workflow (see [Using environments for deployments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)).
  - Environment-level secret `GH_APP_PRIVATE_KEY` that contains the PEM-formatted private key. The workflow passes this value to the Bicep parameter `githubAppPrivateKey`, which in turn stores it in Azure Key Vault.
  - Optional repository secret `GITHUB_PAT_RUNNER` is still honored for legacy deployments that rely on PAT authentication.
- **Optional inputs**
  - Provide a bespoke parameters file (for example `infra/parameters.prod.json`) when dispatching the workflow to align with environment-specific names, or update the lookup table in the workflow to match your naming standards.
  - Override the default image tag suffix (defaults to `v${{ github.run_number }}`) when integrating with release pipelines.

## 6. Configuration Guidance

| Parameter                     | Description                                                                                                     | Source                                                                                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `location`                    | Azure region for all resources; align with Container Apps availability.                                         | Bicep parameter                                                                                                                                      |
| `baseName`                    | Base name used to compose resource names (workspace/env/job).                                                   | Bicep parameter                                                                                                                                      |
| `containerAppEnvironmentName` | Name for the Container Apps managed environment (defaults to `${baseName}-env`).                                | Bicep parameter                                                                                                                                      |
| `containerImage`              | Fully qualified runner image (e.g. `myacr.azurecr.io/github-actions-runner:1.0`).                               | Bicep parameter                                                                                                                                      |
| `acrName`                     | Azure Container Registry name created by the deployment. Must be globally unique.                               | Bicep parameter                                                                                                                                      |
| `githubOwner`/`githubRepo`    | GitHub owner and repo. The script infers these from `-GitHubRepo`.                                              | Bicep/script                                                                                                                                         |
| `githubPatSecretName`         | Secret alias used inside the job for PAT fallback (default `personal-access-token`).                            | Bicep parameter                                                                                                                                      |
| `githubPatSecretValue`        | Secure PAT value when GitHub App authentication is unavailable.                                                 | Bicep/script input                                                                                                                                   |
| `githubAppApplicationId`      | GitHub App identifier used by runners and the KEDA scaler.                                                      | Bicep parameter                                                                                                                                      |
| `githubAppInstallationId`     | GitHub App installation ID scoped to the target org/repository.                                                 | Bicep parameter                                                                                                                                      |
| `githubAppKeySecretName`      | Secret alias created in Key Vault to expose the GitHub App private key to Container Apps.                       | Bicep parameter                                                                                                                                      |
| `githubAppPrivateKey`         | PEM-formatted private key for the GitHub App; stored in Key Vault during deployment.                            | Bicep/script input                                                                                                                                   |
| `userAssignedIdentityId`      | Optional user-assigned managed identity resource ID for registry pulls.                                         | Bicep/CLI                                                                                                                                            |
| `virtualNetworkAddressPrefix` | Address space for the project virtual network.                                                                  | Bicep parameter                                                                                                                                      |
| `containerAppsSubnetPrefix`   | Dedicated subnet delegated to `Microsoft.App/environments`.                                                     | Bicep parameter                                                                                                                                      |
| `platformReservedCidr`        | Internal range reserved for ACA infrastructure (Consumption environment). Must not overlap with other prefixes. | Bicep parameter; see [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters)     |
| `platformReservedDnsIp`       | DNS IP inside `platformReservedCidr` used by ACA infrastructure.                                                | Bicep parameter; see [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters)     |
| `dockerBridgeCidr`            | Docker bridge IP range for the environment.                                                                     | Bicep parameter; see [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters)     |
| `internalEnvironment`         | Boolean flag to deploy an internal-only environment without public ingress.                                     | Bicep parameter; see [Networking in Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/networking?tabs=bash#accessibility-level) |
| `workloadProfiles`            | Array of workload profile definitions. Defaults to a Consumption profile to satisfy delegated subnet requirements. | Bicep parameter; see [Workload profiles in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/workload-profiles-overview)  |

**Secrets strategy**

- Persist the GitHub App private key as a GitHub environment secret (`GH_APP_PRIVATE_KEY`). The bootstrap workflow injects it into the Bicep deployment, which copies the value into Azure Key Vault and grants the Container Apps job identity `Key Vault Secrets User`. Refer to [Store secrets in Azure Container Apps](https://learn.microsoft.com/azure/container-apps/manage-secrets?tabs=portal-bicep#store-secrets-in-azure-container-apps).
- Retrieve sensitive values locally with `Microsoft.PowerShell.SecretManagement` rather than embedding strings in parameter files, for example `Get-Secret -Name 'GitHubAppPrivateKey'`. See [SecretManagement overview](https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview).
- Retain the PAT parameters only when GitHub App authentication is unavailable; the Bicep template continues to support PAT-based KEDA scaling as a fallback path.
- For federated credentials, configure GitHub OIDC trust with [`Create-FederatedCredential.ps1`](./scripts/Create-FederatedCredential.ps1). Graph cmdlets reference: [Microsoft Graph PowerShell overview (beta)](https://learn.microsoft.com/powershell/microsoftgraph/overview?view=graph-powershell-beta).

## 7. Security & Compliance Considerations

- Protect the GitHub App private key by limiting access to the GitHub environment secret and Azure Key Vault; regenerate keys on a rotation schedule. When using the PAT fallback, restrict scope and rotate regularly per [GitHub self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security).
- Use managed identities for registry/image pull wherever feasible; assign `AcrPull` via [`New-AzRoleAssignment`](https://learn.microsoft.com/powershell/module/az.resources/new-azroleassignment?view=azps-latest).
- Store secrets in Key Vault with RBAC and logging. See [Azure Key Vault overview](https://learn.microsoft.com/azure/key-vault/general/overview).
- Harden runner image by installing minimum tooling, patching base images, and disabling long-lived credentials. Ensure containers run as non-root when possible.
- Enable diagnostic logs and alerts using Azure Monitor. See [Monitor Container Apps](https://learn.microsoft.com/azure/container-apps/monitor).

## 8. Operations & Day-2 Management

- **Scaling**: Adjust `--min-executions`, `--max-executions`, and `targetWorkflowQueueLength` to fit workload demand. KEDA poll interval defaults to 30s; consider rate-limit impact.
- **Monitoring**: Query job execution history using [`az containerapp job execution list`](https://learn.microsoft.com/cli/azure/containerapp/job/execution) and ingest logs to Log Analytics for alerting.
- **Cost**: Jobs charge only while running. Optimize by keeping images lean, right-sizing CPU/memory (`--cpu`, `--memory`), and pruning unused container images in ACR.
- **Image updates**: Rebuild/tag runner images with patched dependencies then redeploy; Container Apps job picks latest version on next execution.

## 9. Testing & Validation

- Author Pester 5.x tests targeting deployment scripts; use [Pester overview](https://learn.microsoft.com/powershell/scripting/testing/overview?view=powershell-7.4) as reference.
- Implement smoke tests to verify runner registration, GitHub App token issuance (or PAT fallback), and scaling events.
- Consider integration tests that queue synthetic workflows and assert log outputs.
- Trigger the sample GitHub Actions workflow at `.github/workflows/demo-self-hosted-runner.yml` via the **Run workflow** button in GitHub. It fans out to nine matrix jobs (`max-parallel: 9`) targeting the `self-hosted, azure-container-apps` labels, which exercises horizontal scale-out of the Container Apps job. Monitor executions with `az containerapp job execution list --name <jobName> --resource-group <rg>` (https://learn.microsoft.com/cli/azure/containerapp/job/execution) and observe logs in Log Analytics to confirm all nine runners complete successfully.

## 10. Troubleshooting Guide

| Symptom                              | Diagnostic steps                                                           | Resolution                                                                                                                                                                                                              |
| ------------------------------------ | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Job executions stuck in `Pending`    | `az containerapp job execution list` and inspect Log Analytics for errors. | Validate ACR permissions, managed identity assignments, and image availability.                                                                                                                                         |
| Runner fails to register with GitHub | Check container logs for App key or PAT token errors.                      | Verify `APP_ID`/`APP_INSTALLATION_ID` env vars and that the Key Vault secret is accessible; if using PAT fallback, regenerate the PAT and confirm `REGISTRATION_TOKEN_API_URL` plus egress to `https://api.github.com`. |
| KEDA scaler not triggering           | Verify scale rule metadata (owner, repos, labels).                         | Ensure PAT scopes are correct and API rate limits not exceeded. Consider enabling ETags per KEDA guidance.                                                                                                              |
| Federated credential creation fails  | Inspect `Create-FederatedCredential.ps1` verbose output.                   | Confirm Microsoft Graph permissions (`Application.ReadWrite.All`) and app object ID accuracy.                                                                                                                           |

## 11. Cleanup & Decommissioning

```powershell
Remove-AzResourceGroup -Name $RESOURCE_GROUP -Force
```

Command reference: [`Remove-AzResourceGroup`](https://learn.microsoft.com/powershell/module/az.resources/remove-azresourcegroup?view=azps-latest).

Additional tasks:

- Delete GitHub PATs and revoke any remaining secrets.
- Remove federated credentials from Entra application if no longer required.
- Purge container images or delete the ACR to avoid storage charges.

## 12. Reference Documentation

- Azure Container Apps jobs: [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/container-apps/jobs)
- Scaling Container Apps: [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/container-apps/scale-app)
- GitHub self-hosted runner security: [docs.github.com](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners)
- Azure Container Apps tutorial (GitHub runners): [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/container-apps/tutorial-ci-cd-runners-jobs?tabs=powershell&pivots=container-apps-jobs-self-hosted-ci-cd-github-actions)
- KEDA GitHub runner scaler: [keda.sh](https://keda.sh/docs/latest/scalers/github-runner/)
- Azure DevOps self-hosted agents (for comparison): [learn.microsoft.com](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/linux-agent?view=azure-devops)
- Container Apps jobs overview and configuration: https://learn.microsoft.com/en-us/azure/container-apps/jobs?tabs=azure-cli
- Container registry integration and managed identity usage for Container Apps: https://learn.microsoft.com/en-us/azure/container-apps/containers?tabs=bicep#container-registries
- Container Apps environment log configuration with Log Analytics: https://learn.microsoft.com/en-us/azure/container-apps/environment?tabs=bicep#logs
- Creating Log Analytics workspaces: https://learn.microsoft.com/en-us/azure/azure-monitor/logs/quick-create-workspace
- KEDA GitHub runner scaler metadata requirements (labels, queue length): https://keda.sh/docs/latest/scalers/github-runner/
- GitHub repository for sample implementation: https://github.com/Azure-Samples/container-apps-ci-cd-runner-tutorial.git
