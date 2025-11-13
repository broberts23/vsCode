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
| Layer | Component | Notes |
| --- | --- | --- |
| Identity | User-assigned managed identity (optional) | Authenticates Container Apps job to pull private images and call Azure APIs. |
| Compute | Azure Container Apps environment & jobs | Event-driven jobs host ephemeral GitHub Actions runners. See [Jobs in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/jobs). |
| Network | Azure Virtual Network + delegated subnet & NSG | Provides private connectivity for the Container Apps environment and restricts ingress/egress per [Custom virtual networks for Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks?tabs=bicep). |
| Image Registry | Azure Container Registry | Stores hardened runner images; configured for ARM audience tokens for managed identity pulls. |
| Secrets | Azure Key Vault or PowerShell SecretManagement | Stores GitHub PAT or app key used for scaler authentication. |
| Observability | Log Analytics workspace & Azure Monitor | Captures job execution history, container logs, and scaling metrics. |
| Scaling | KEDA GitHub runner scaler | Evaluates `targetWorkflowQueueLength` to add/remove executions. Refer to [KEDA GitHub runner scaler](https://keda.sh/docs/latest/scalers/github-runner/). |

**Lifecycle**
1. GitHub workflow targeting the `self-hosted` label queues a job.
2. KEDA scaler polls GitHub API using PAT/app credentials and detects the queued workflow.
3. Container Apps job spins up a runner replica, authenticates back to GitHub, executes, then exits.
4. Logs stream to Log Analytics; jobs scale back to zero when idle (default cooldown 300 seconds per [Container Apps scaling behavior](https://learn.microsoft.com/en-us/azure/container-apps/scale-app#scale-behavior)).

## 3. Prerequisites
- **Azure**
  - Active subscription with `Microsoft.App` and `Microsoft.OperationalInsights` resource providers registered. Use [`Register-AzResourceProvider`](https://learn.microsoft.com/powershell/module/az.resources/register-azresourceprovider?view=azps-latest).
  - Permissions: `Contributor` to target resource group, `AcrPull` on ACR if using separate identity.
  - Azure CLI (for ad-hoc validation) and PowerShell 7.4 with Az modules. Install Az via [`Install-Module`](https://learn.microsoft.com/powershell/module/powershellget/install-module?view=powershell-7.4).
- **GitHub**
  - Repository (private recommended) with permission to administer self-hosted runners.
  - PAT with `Actions: Read`, `Administration: ReadWrite`, `Metadata: Read` scopes as outlined in the tutorial.
- **Local tooling**
  - Docker or OCI-build capable workstation to author Dockerfiles (remote ACR build reduces local dependencies).
  - Logged-in session via [`Connect-AzAccount`](https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest) and optionally [`Connect-MgGraph`](https://learn.microsoft.com/powershell/microsoftgraph/authentication/connect-mggraph?view=graph-powershell-beta) for federated credential automation.

## 4. Repository Structure & Artifacts
```
project-github-runner/
├─ README.md                     # Deployment guide (this file)
├─ infra/
│  ├─ parameters.sample.json     # Template for parameter overrides
│  ├─ main.bicep                 # Composes workspace, environment, (optional) ACR, and the job
│  ├─ containerapps/             # Bicep modules (job, env, registry)
│  └─ network/
│     └─ vnet.bicep              # Virtual network, delegated subnet, and NSG for Container Apps
└─ scripts/
   ├─ ContainerApps-Deploy-Job.ps1        # Creates Container Apps job via Azure CLI
   ├─ ContainerInit.ps1                   # Optional container init hook to install modules
   ├─ Create-FederatedCredential.ps1      # Adds Entra federated credential for GitHub OIDC
   └─ Deploy-GitHubRunner.ps1             # End-to-end deployment wrapper using Bicep
```

> **Action**: Copy `infra/parameters.sample.json` to `infra/parameters.dev.json` (or similar) and adjust per environment. Keep secrets external to source control.

## 5. Deployment Workflow (End-to-End)
All commands assume PowerShell 7.4 (`pwsh`) with execution from the repository root.

1. **Authenticate & prepare Azure environment**
    ```powershell
    # Sign in interactively
    Connect-AzAccount

    # Ensure required providers are registered
    Register-AzResourceProvider -ProviderNamespace Microsoft.App
    Register-AzResourceProvider -ProviderNamespace Microsoft.OperationalInsights
    ```

2. **Install/Update Az modules**
    ```powershell
    Install-Module -Name Az -Scope CurrentUser -Force
    Update-Module -Name Az.App -ErrorAction SilentlyContinue
    ```
    Reference: [`Install-Module`](https://learn.microsoft.com/powershell/module/powershellget/install-module?view=powershell-7.4), [`Update-Module`](https://learn.microsoft.com/powershell/module/powershellget/update-module?view=powershell-7.4).

3. **Set environment context**
    ```powershell
    $RESOURCE_GROUP = 'rg-github-runner-dev'
    $LOCATION       = 'eastus'
    $ENVIRONMENT    = 'env-github-runner'
    $ACR_NAME       = 'ghrunnerdevacr'
    $IMAGE_NAME     = 'github-actions-runner:1.0'
    $JOB_NAME       = 'github-actions-runner-job'
    $REPO_OWNER     = 'your-org'
    $REPO_NAME      = 'your-repo'
    $GITHUB_REPO    = "$REPO_OWNER/$REPO_NAME"
    ```


4. **Build and push runner image**
    - Create ACR: [`New-AzContainerRegistry`](https://learn.microsoft.com/powershell/module/az.containerregistry/new-azcontainerregistry?view=azps-latest).
    - Enable ARM audience tokens if required (`az acr config authentication-as-arm update`).
    - Trigger cloud build against sample Dockerfile (replace repository as needed):
        ```powershell
        az acr build `
          --registry $ACR_NAME `
          --image $IMAGE_NAME `
          --file Dockerfile.github `
          https://github.com/Azure-Samples/container-apps-ci-cd-runner-tutorial.git
        ```
	Documentation: [Azure Container Registry build](https://learn.microsoft.com/azure/container-registry/container-registry-tutorial-quick-task).

5. **Customize Bicep parameters**
    ```powershell
    Copy-Item -Path ./infra/parameters.sample.json -Destination ./infra/parameters.dev.json -Force
    # Edit the copy to set values (location, environment name, ACR details, secrets references, etc.)
    ```
	Bicep concepts: [Bicep overview](https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview).

6. **Deploy infrastructure**
        ```powershell
        # Construct full image reference and deploy
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
            deployContainerRegistry  = @{ value = $true }                    # or false if using existing ACR
            acrName                  = @{ value = $ACR_NAME }                # when creating a new ACR
            githubPatSecretValue     = @{ value = '<secure-pat-or-use-secretmanagement>' }
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
	- Ensures the resource group exists via [`New-AzResourceGroup`](https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroup?view=azps-latest).
	- Deploys Bicep using [`New-AzResourceGroupDeployment`](https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest).
  - Optionally retrieves a GitHub runner registration token and injects it as `RUNNER_TOKEN` environment variable.
	- Adds a federated credential to the job’s managed identity using Microsoft Graph (beta) if identity outputs are available.
	- Applies virtual network defaults when `-TemplateParameters` omits them; override as needed per [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters).

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

## 6. Configuration Guidance
| Parameter | Description | Source |
| --- | --- | --- |
| `location` | Azure region for all resources; align with Container Apps availability. | Bicep parameter |
| `baseName` | Base name used to compose resource names (workspace/env/job). | Bicep parameter |
| `containerAppEnvironmentName` | Name for the Container Apps managed environment (defaults to `${baseName}-env`). | Bicep parameter |
| `containerImage` | Fully qualified runner image (e.g. `myacr.azurecr.io/github-actions-runner:1.0`). | Bicep parameter |
| `acrName` | Azure Container Registry name (when creating a new ACR). | Bicep parameter |
| `deployContainerRegistry` | Whether to create a new ACR (`true`) or use existing (`false`). | Bicep parameter |
| `existingAcrLoginServer`/`existingAcrResourceId` | Required when reusing an existing ACR. | Bicep parameter |
| `githubOwner`/`githubRepo` | GitHub owner and repo. The script infers these from `-GitHubRepo`. | Bicep/script |
| `githubPatSecretName` | Secret alias used inside the job (default `personal-access-token`). | Bicep parameter |
| `githubPatSecretValue` | Secure PAT value (or use SecretManagement/Key Vault in the script). | Bicep/script input |
| `userAssignedIdentityId` | Optional user-assigned managed identity resource ID for registry pulls. | Bicep/CLI |
| `virtualNetworkAddressPrefix` | Address space for the project virtual network. | Bicep parameter |
| `containerAppsSubnetPrefix` | Dedicated subnet delegated to `Microsoft.App/environments`. | Bicep parameter |
| `platformReservedCidr` | Internal range reserved for ACA infrastructure (Consumption environment). Must not overlap with other prefixes. | Bicep parameter; see [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters) |
| `platformReservedDnsIp` | DNS IP inside `platformReservedCidr` used by ACA infrastructure. | Bicep parameter; see [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters) |
| `dockerBridgeCidr` | Docker bridge IP range for the environment. | Bicep parameter; see [Networking parameters](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters) |
| `internalEnvironment` | Boolean flag to deploy an internal-only environment without public ingress. | Bicep parameter; see [Networking in Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/networking?tabs=bash#accessibility-level) |

**Secrets strategy**
- Prefer Azure Key Vault or SecretManagement to avoid plaintext storage. See [SecretManagement overview](https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview).
- For federated credentials, configure GitHub OIDC trust with [`Create-FederatedCredential.ps1`](./scripts/Create-FederatedCredential.ps1). Graph cmdlets reference: [Microsoft Graph PowerShell overview (beta)](https://learn.microsoft.com/powershell/microsoftgraph/overview?view=graph-powershell-beta).

## 7. Security & Compliance Considerations
- Restrict GitHub PAT scope; rotate regularly per [GitHub self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security).
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
- Implement smoke tests to verify runner registration, PAT validity, and scaling events.
- Consider integration tests that queue synthetic workflows and assert log outputs.

## 10. Troubleshooting Guide
| Symptom | Diagnostic steps | Resolution |
| --- | --- | --- |
| Job executions stuck in `Pending` | `az containerapp job execution list` and inspect Log Analytics for errors. | Validate ACR permissions, managed identity assignments, and image availability. |
| Runner fails to register with GitHub | Check container logs for PAT/token errors. | Regenerate PAT, ensure `REGISTRATION_TOKEN_API_URL` env var, confirm network egress to `https://api.github.com`. |
| KEDA scaler not triggering | Verify scale rule metadata (owner, repos, labels). | Ensure PAT scopes are correct and API rate limits not exceeded. Consider enabling ETags per KEDA guidance. |
| Federated credential creation fails | Inspect `Create-FederatedCredential.ps1` verbose output. | Confirm Microsoft Graph permissions (`Application.ReadWrite.All`) and app object ID accuracy. |

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