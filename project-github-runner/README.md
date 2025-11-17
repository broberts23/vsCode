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

### GitHub App permissions you must grant

GitHub only issues runner registration tokens when the calling credential has the correct fine-grained permission for the endpoint you target. Configure your GitHub App with the following access levels before installing it on your repo or organization (see the REST reference for the registration endpoints at https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-a-registration-token-for-a-repository and https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-a-registration-token-for-an-organization):

| Runner scope (`githubRunnerScope`)       | Registration endpoint                                               | Required GitHub App permission                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `repo` (user-owned or single repository) | `POST /repos/{owner}/{repo}/actions/runners/registration-token`     | **Repository** permissions → **Administration: Read & write**                                              |
| `org`                                    | `POST /orgs/{org}/actions/runners/registration-token`               | **Organization** permissions → **Self-hosted runners: Read & write**                                       |
| `ent`                                    | `POST /enterprises/{enterprise}/actions/runners/registration-token` | Enterprise administrators must grant the **Self-hosted runners** permission on the enterprise installation |

Use `githubRunnerScope: "repo"` when `githubOwner` is a personal account such as `broberts23`, so the template targets the repository endpoints and the GitHub App only needs **Repository → Administration (Read & write)** plus access to that repo. Use `githubRunnerScope: "org"` only when `githubOwner` is a real GitHub Organization and the app is installed on that organization with **Organization → Self-hosted runners (Read & write)**.

Be sure the installation is granted access to the exact repositories you list under `githubRunnerRepositories`. If the permission or repository access is missing, GitHub responds with `403 Resource not accessible by integration`; that message indicates the installation token lacks the scope documented above (see https://docs.github.com/en/rest/using-the-rest-api/troubleshooting#resource-not-accessible).

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
- `containerImage` (temporary placeholder, for example `example.azurecr.io/github-actions-runner:0.0.0`)
- `acrName`
- `githubOwner` / `githubRepo`
- `githubRunnerScope` (set to `repo` when `githubOwner` is a user account like `broberts23`; use `org` only when `githubOwner` is a real GitHub Organization)
- GitHub auth: either `githubAppApplicationId`/`githubAppInstallationId`/`githubAppPrivateKey` or `githubPatSecretValue`.

At this point you have not created the ACR or image yet; the initial deployment will create the Azure resources and bootstrap the job with a placeholder image value.

## 3. Deploy Azure infra (first pass)

Deploy the Bicep template once to create the resource group, Container Apps environment, Log Analytics workspace, and Azure Container Registry. The job will be deployed but will reference your temporary `containerImage` until you build and push the real one.

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

After this completes you will have an ACR named according to `acrName` in your parameters file.

## 4. Build and push the runner image

Now that ACR exists, build the runner image locally and push it to that registry.

```powershell
$ACR_NAME  = '<acr-name-from-parameters>'
$IMAGE_TAG = "$ACR_NAME.azurecr.io/github-actions-runner:2.329.0"

az acr login --name $ACR_NAME
./scripts/Build-GitHubRunnerImage.ps1 -ImageTag $IMAGE_TAG -Push
```

Update `containerImage` in `infra/parameters.dev.json` to match `$IMAGE_TAG`.

## 5. Redeploy infra to pick up the image

Run the deployment script again so the Container Apps job points at the image you just pushed.

```powershell
./scripts/Deploy-GitHubRunner.ps1 `
  -ResourceGroupName $RESOURCE_GROUP `
  -Location $LOCATION `
  -GitHubRepo $GITHUB_REPO `
  -TemplatePath ./infra/main.bicep `
  -TemplateParametersPath ./infra/parameters.dev.json
```

This second pass updates the job definition to use the correct `containerImage` while reusing the existing resource group, Container Apps environment, Log Analytics workspace, and ACR.

## 6. Point a workflow at the runners

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

## 7. Clean up

```powershell
Remove-AzResourceGroup -Name $RESOURCE_GROUP -Force
```

This removes all Azure resources created by the deployment. Remember to delete/rotate any GitHub PATs or GitHub App keys you created.

## Troubleshooting GitHub App authentication

- **403 `Resource not accessible by integration`**: This message means the GitHub App installation token does not have the permission documented for the registration endpoint you are calling. Revisit the table above to ensure Repository → Administration (read & write) or Organization → Self-hosted runners (read & write) is enabled, then re-authorize the installation so the updated permission applies (see https://docs.github.com/en/rest/using-the-rest-api/troubleshooting#resource-not-accessible).
- **Wrong scope**: If `githubRunnerScope` is `org` but `githubOwner` is a personal account, GitHub will route you to `/orgs/{owner}` and return 404/403. Set the scope to `repo` for user-owned repositories so both the runner and scaler call `/repos/{owner}/{repo}`.
- **Missing repository access**: Opening the GitHub App installation page shows the repositories granted to the installation. Ensure every repo monitored by `githubRunnerRepositories` is selected or switch the installation to "All repositories".
- **Inspecting errors**: The runner container now logs the HTTP status code and body for every GitHub API call, so you can see the exact error payload from `POST .../registration-token`. The response also includes the `X-Accepted-GitHub-Permissions` header, which tells you what permission GitHub expected for that endpoint.

## More details

For architecture diagrams, parameter explanations, KEDA tuning, and security discussion, see `blog.md` in this folder.
