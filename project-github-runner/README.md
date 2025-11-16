# Azure Container Apps Self-Hosted GitHub Runner

This repo deploys ephemeral GitHub Actions runners on Azure Container Apps jobs using Bicep and PowerShell. Use this `README` as a quick-start; see `blog.md` for the deep dive and design rationale.

## What this gives you

- An Azure Container Apps environment, virtual network, Log Analytics workspace, and Azure Container Registry.
- An event-driven Container Apps job that runs short‑lived GitHub Actions runners.
- KEDA GitHub runner scaler wired to your repo/organization via PAT or GitHub App auth.

## Prerequisites

- PowerShell 7.4 (`pwsh`) and Az modules.
- Azure subscription with `Microsoft.App`, `Microsoft.OperationalInsights`, and `Microsoft.ContainerRegistry` providers registered.
- GitHub repository where you can configure self-hosted runners.
- Either:
  - GitHub App (recommended) with App ID, installation ID, and PEM private key, or
  - Personal Access Token (PAT) with `repo`/`workflow` scopes (fallback).

## 1. Clone and inspect

```bash
git clone https://github.com/<your-org>/<your-repo>.git
cd project-github-runner
```

Key paths:

- Infra: `infra/main.bicep`, `infra/parameters.sample.json`
- Scripts: `scripts/Deploy-GitHubRunner.ps1`, `scripts/Build-GitHubRunnerImage.ps1`
- Runner image: `Dockerfile.github`, `github-actions-runner/entrypoint.sh`

## 2. Prepare parameters

```powershell
Copy-Item ./infra/parameters.sample.json ./infra/parameters.dev.json -Force
```

Edit `infra/parameters.dev.json` and set at minimum:

- `location`
- `baseName`
- `containerImage` (for example `myacr.azurecr.io/github-actions-runner:2.329.0`)
- `acrName`
- `githubOwner` / `githubRepo`
- GitHub auth: either `githubAppApplicationId`/`githubAppInstallationId`/`githubAppPrivateKey` or `githubPatSecretValue`.

## 3. Build and push the runner image

```powershell
$ACR_NAME  = 'myacrname'
$IMAGE_TAG = "$ACR_NAME.azurecr.io/github-actions-runner:2.329.0"

az acr login --name $ACR_NAME
./scripts/Build-GitHubRunnerImage.ps1 -ImageTag $IMAGE_TAG -Push
```

Update `containerImage` in your parameters file to match `$IMAGE_TAG`.

## 4. Deploy infra with PowerShell

```powershell
$RESOURCE_GROUP = 'rg-github-runner-dev'
$LOCATION       = 'eastus'
$GITHUB_REPO    = 'your-org/your-repo'

./scripts/Deploy-GitHubRunner.ps1 `
  -ResourceGroupName $RESOURCE_GROUP `
  -Location $LOCATION `
  -GitHubRepo $GITHUB_REPO `
  -TemplatePath ./infra/main.bicep `
  -TemplateParametersPath ./infra/parameters.dev.json
```

The script will create the resource group (if needed), deploy `infra/main.bicep`, provision ACR, and wire the Container Apps job, identities, and Key Vault (for GitHub App private key).

## 5. Point a workflow at the runners

In your GitHub repo, configure a workflow to target the labels in `runnerLabels` (default `self-hosted,azure-container-apps`):

```yaml
runs-on:
  - self-hosted
  - azure-container-apps
```

Trigger the workflow (for example with `workflow_dispatch`). KEDA will see queued jobs and start Container Apps job executions.

You can monitor executions with:

```bash
az containerapp job execution list \
  --name <job-name> \
  --resource-group <resource-group> \
  --output table
```

## 6. Clean up

```powershell
Remove-AzResourceGroup -Name $RESOURCE_GROUP -Force
```

This removes all Azure resources created by the deployment. Remember to delete/rotate any GitHub PATs or GitHub App keys you created.

## More details

For architecture diagrams, parameter explanations, KEDA tuning, and security discussion, see `blog.md` in this folder.
