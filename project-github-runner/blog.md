# Self‑Hosted GitHub Runners on Azure Container Apps: Architecture, Deployment, and KEDA Scaling

## Introduction

This post is a practical deep dive into running self‑hosted GitHub Actions runners on Azure Container Apps (ACA). The goal: ephemeral, on‑demand compute that scales up only when there are GitHub workflow jobs in the queue and scales to zero when idle. You’ll see how the resources fit together (Log Analytics, Container Apps environment, Azure Container Registry), how the runner containers register with GitHub, how workflows target these runners, and how KEDA automatically scales job executions based on load.

If you maintain repositories that need custom tooling, access to private networks, or predictable performance characteristics, self‑hosted runners on ACA jobs give you serverless elasticity with infrastructure‑as‑code repeatability.

Key references:

- Jobs in Azure Container Apps: https://learn.microsoft.com/azure/container-apps/jobs?tabs=azure-cli
- Containers in Azure Container Apps (registries, managed identities): https://learn.microsoft.com/azure/container-apps/containers?tabs=bicep
- Tutorial (GitHub pivot): https://learn.microsoft.com/azure/container-apps/tutorial-ci-cd-runners-jobs?tabs=bicep&pivots=container-apps-jobs-self-hosted-ci-cd-github-actions
- KEDA GitHub runner scaler: https://keda.sh/docs/latest/scalers/github-runner/

## Project summary

The repo is intentionally split into two experiences:

- `README.md` is the quick-start: copy a parameters file, build an image, run one script, and point a workflow at the labels.
- `blog.md` (this post) is the design notebook: why the Bicep looks the way it does, why KEDA is wired this way, and what trade-offs I made around identity, networking, and security.

At a resource level, the composed Bicep template brings up everything this pattern needs in one shot: a Log Analytics workspace wired into a Container Apps managed environment, an Azure Container Registry (ACR) with managed identity pull configured, and a virtual network with a delegated subnet and network security group to keep traffic on your own address space. On top of that it defines the Azure Container Apps event‑driven job that runs the GitHub Actions runner image, registers with your repo or organization, and exits when the workflow completes, plus a KEDA `github-runner` scaler that watches your GitHub queue and decides when to trigger executions. The repo also includes a small container build scaffold (`Dockerfile.github`, `github-actions-runner/entrypoint.sh`, and `scripts/Build-GitHubRunnerImage.ps1`) that packages the upstream runner release (`v2.329.0` at https://github.com/actions/runner/releases/tag/v2.329.0) with the extra tooling you are likely to need.

When the deployment finishes, it returns the environment ID, job ID, managed identity principal IDs, and ACR metadata so you can plug those identifiers into dashboards or additional automation without hunting for them in the portal.

## Repository structure (relevant parts)

```
project-github-runner/
├─ Dockerfile.github             # Dockerfile for the GitHub Actions runner image
├─ github-actions-runner/
│  └─ entrypoint.sh              # Container entrypoint configuring the runner
├─ README.md                     # Deployment guide and architecture overview
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

## Architecture overview

At a high level, the moving pieces line up in a pretty natural way. An Azure Monitor Log Analytics workspace captures container logs, scale events, and job execution history at the environment level. That is why `infra/main.bicep` computes the workspace name from `baseName` and location and then passes both the workspace ID and a shared key into the managed environment module. A single Container Apps environment then hosts the job and acts as the security and logging boundary for CI workloads—anything that can touch internal build systems or package feeds lives in this environment or its peered VNets.

Network-wise, a dedicated virtual network and delegated subnet isolate the environment, and a network security group lets you enforce egress controls or lock down ingress. This trades a bit of deployment complexity for the ability to keep runners off the public internet. The runner image is pulled from ACR (or another registry), and I default to managed identity authentication so there are no registry passwords or admin credentials in the deployment. The Azure Container Apps job has the system-assigned identity enabled with ACR pull rights and, by default, the deployment also creates and attaches a user-assigned managed identity that you can reuse across redeployments or share with other workloads.

Secrets finish the picture. GitHub App metadata (App ID and installation ID) arrives via GitHub environment variables and the private key arrives as an environment secret. The bootstrap pipeline passes those into the Bicep deployment, which copies the PEM into Azure Key Vault and wires a secret reference into the Container Apps job so both the runner bootstrap and KEDA scaler can authenticate without hard-coding secrets in Bicep. On top of that, the KEDA scaler queries GitHub for queued jobs using either PAT or GitHub App credentials; when the queue length exceeds your target, KEDA triggers ACA job executions and each execution runs one ephemeral runner container that exits when the workflow completes.

Flow:

1. A GitHub workflow queues a job targeting your self‑hosted labels.
2. The KEDA scaler polls the GitHub API, scoped to your org/repo and labels, and detects queued work.
3. ACA starts N job executions (bounded by min/max per interval). Each execution creates a pod with the runner container.
4. The runner registers with GitHub, picks up the job, executes steps, and exits.
5. ACA marks the execution complete. With no pending work, subsequent polls result in zero executions and the job scales to zero.

The rest of this post walks through the Bicep and runner image design in more detail, explaining why certain patterns look “heavier” than a minimal sample but pay off in day‑2 operations.

## Demo GitHub Actions pipeline

To make the experience tangible, the repository includes `.github/workflows/demo-self-hosted-runner.yml`. When you dispatch this workflow from the **Actions** tab it spins up a simple matrix of nine parallel jobs, each targeting the `self-hosted` and `azure-container-apps` labels so work naturally lands on the Container Apps runners created by the Bicep deployment. The matrix uses `max-parallel: 9` so all jobs can run at once, which forces the KEDA scaler to scale the job up to nine containers (bounded by `maxExecutions`) and gives you something interesting to watch.

Inside each job, the steps record the runner host name, verify that PowerShell 7.4 is available, and simulate a short workload so the container stays alive long enough for you to observe behavior. When you trigger the workflow, GitHub places nine jobs in the queue (your `runnerLabels` parameter must match the labels in the workflow), the scaler sees the queue depth (with `targetWorkflowQueueLength` defaulting to `1`), and schedules executions in the Container Apps environment. Each execution registers an ephemeral runner, processes its slice of the matrix, and exits. You can monitor progress with `az containerapp job execution list --name <jobName> --resource-group <rg>`, drill into individual executions with `az containerapp job execution show --name <executionName> --job-name <jobName> --resource-group <rg>`, and use Log Analytics to look at job output.

In practice this little pipeline becomes a “smoke test” for the whole setup: it exercises scaling, confirms network access, and gives you telemetry before you trust the pattern with production workloads.

## Container image build workflow

The runner image is built locally from `Dockerfile.github`, which uses the official GitHub Actions runner base image (`ghcr.io/actions/actions-runner:2.329.0`) and adds an entrypoint script to handle registration. The `scripts/Build-GitHubRunnerImage.ps1` PowerShell script simplifies building and pushing the image to your ACR:

```powershell
./scripts/Build-GitHubRunnerImage.ps1 `
  -ImageTag "$ACR_NAME.azurecr.io/github-actions-runner:2.329.0" `
  -Push
```

The script wraps `docker build`/`docker push`, allowing you to target alternative architectures or versions by adjusting parameters. Authenticate to your registry (for example, `az acr login --name $ACR_NAME`) before pushing. Because the Bicep deployment provisions the Azure Container Registry and grants the job managed identity `AcrPull`, update `containerImage` in your Bicep parameters to reference the new tag and redeploy.

## Networking uplift and VNet integration

Enterprise deployments often require private networking, static routing requirements, or traffic inspection. The `network/vnet.bicep` module provisions a virtual network, delegated subnet, and optional custom NSG rules so the Container Apps environment can attach directly to your address space. During deployment, the main Bicep template passes the subnet resource ID to the environment module, enabling [VNet integration](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks?tabs=bicep).

Key parameters are exposed to keep address planning flexible:

- `virtualNetworkAddressPrefix` and `containerAppsSubnetPrefix` define the VNet and infrastructure subnet CIDR blocks.
- `platformReservedCidr`, `platformReservedDnsIp`, and `dockerBridgeCidr` surface the optional networking ranges documented in [Networking parameters for Container Apps environments](https://learn.microsoft.com/en-us/azure/container-apps/vnet-custom?tabs=bash#networking-parameters), preventing conflicts with peered VNets.
- `internalEnvironment` toggles whether the managed environment is created as internal-only, removing the public VIP. See https://learn.microsoft.com/azure/container-apps/networking?tabs=bash#accessibility-level.

By managing the VNet resources in Bicep you can apply Azure Policy, configure diagnostics, and enforce NSG rules consistently. Downstream workloads—build agents, package feeds, artifact stores—can live in the same VNet or attached spokes, enabling end-to-end private networking without exposing the runners to the public internet.

I deliberately stopped short of deploying auxiliary perimeter services (Azure Firewall, Private Endpoints, or private DNS zones) in this repo to keep the focus on the runner pattern itself. Those pieces tend to be very environment‑specific. The VNet module is designed so you can plug those in later without re‑architecting the job.

## How GitHub runners work in ACA jobs (end‑to‑end)

### 1) Resource creation (Bicep)

The main template (`infra/main.bicep`) composes a few focused modules:

- `logAnalytics.bicep` provisions a workspace (retention configurable) and returns its IDs.
- `managedEnvironment.bicep` creates the Container Apps environment and connects it to Log Analytics.
- `containerRegistry.bicep` creates ACR and assigns `AcrPull` to a supplied principal.
- `githubRunnerJob.bicep` defines the event‑driven job (`Microsoft.App/jobs`) and KEDA scale rules.

The interesting parts are the glue and the identity wiring in `main.bicep`. For example, runner configuration URLs are normalized up front:

```bicep
var githubApiUrlNormalized = endsWith(githubApiUrl, '/')
  ? substring(githubApiUrl, 0, max(length(githubApiUrl) - 1, 0))
  : githubApiUrl

var githubServerUrlNormalized = endsWith(githubServerUrl, '/')
  ? substring(githubServerUrl, 0, max(length(githubServerUrl) - 1, 0))
  : githubServerUrl
```

Normalizing here avoids subtle bugs later (for example double slashes in REST URLs or mismatched hostnames between the runner and the scaler) and keeps the job module simpler. Similarly, the template computes the runner registration URL and token endpoint based on the `runnerScope` parameter:

```bicep
var githubRunnerUrl = githubRunnerScope == 'org'
  ? '${githubServerUrlNormalized}/${githubOwner}'
  : (githubRunnerScope == 'ent'
      ? '${githubServerUrlNormalized}/enterprises/${githubOwner}'
      : '${githubServerUrlNormalized}/${githubOwner}/${githubRepo}')

var githubRegistrationTokenApiUrl = githubRunnerScope == 'org'
  ? '${githubApiUrlNormalized}/orgs/${githubOwner}/actions/runners/registration-token'
  : (githubRunnerScope == 'ent'
      ? '${githubApiUrlNormalized}/enterprises/${githubOwner}/actions/runners/registration-token'
      : '${githubApiUrlNormalized}/repos/${githubOwner}/${githubRepo}/actions/runners/registration-token')
```

This gives you one template that works for repo, org, or enterprise‑scoped runners without changing the job module.

### 2) Deploying the job

In day‑to‑day use, the deployment flow is straightforward. You create or reuse a resource group and deploy `infra/main.bicep` with parameters for your GitHub owner and repository (or org scope), the container image you want to use for the runner (an ACR path or external registry), and your scaling preferences such as `minExecutions`, `maxExecutions`, `pollingInterval`, and `targetWorkflowQueueLength`. Network and identity parameters control how the job reaches ACR and any internal resources your builds might need. The deployment returns the job and environment IDs, and logs start flowing to Log Analytics automatically.

To keep long‑lived credentials out of source control, the GitHub Actions workflow reads `GH_APP_PRIVATE_KEY` from an environment secret (see https://docs.github.com/actions/security-guides/using-secrets-in-github-actions). The Bicep deployment writes that value into Azure Key Vault and assigns `Key Vault Secrets User` to the job identity, so at runtime the Container Apps secret can reference the vault URI and both the runner entrypoint and KEDA scaler can mint JWTs and installation tokens following https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app.

The KEDA scaler only needs a handful of GitHub details to do its work: who owns the workloads (`owner`), how they are scoped (`runnerScope` as `repo`, `org`, or `ent`), which repositories to watch, which labels to honor, and how aggressively to scale (`targetWorkflowQueueLength` and `pollingInterval`). The job module receives these via parameters such as `runnerScope`, `githubRepositories`, and `scaleRunnerLabels`, so you can tune behavior just by changing parameter values instead of touching the module code.

### 3) Runner bootstrap and registration with GitHub

When a job execution starts, ACA launches the runner container with environment variables and secrets provided by Bicep. The runner process performs the following steps:

1. Exchanges the GitHub App installation token or PAT for a short‑lived registration token via GitHub REST: `POST /repos/{owner}/{repo}/actions/runners/registration-token` (or org/ent variant). The job template includes `REGISTRATION_TOKEN_API_URL` and `GH_URL`/repo for clarity.
2. Configures the runner with your labels and repository/organization context.
3. Registers the runner; it shows up as an online self‑hosted runner in GitHub.
4. Waits for a workflow job assignment; when received, executes all steps.
5. On completion, the container exits. Ephemeral patterns typically remove the runner registration automatically on shutdown.

This lifecycle ensures no idle, permanently registered VMs—each execution is purpose‑built and disposed.

### 4) Using the runners in GitHub Actions

In your workflow YAML, you point jobs at these runners simply by targeting the right labels:

```yaml
runs-on: [self-hosted, azure-container-apps]
```

You can add repo, org, or language-specific labels—`dotnet`, `arm64`, `build-tools`, and so on—to steer jobs toward particular images or toolchains. From GitHub’s perspective, jobs just queue until a matching self‑hosted runner comes online; behind the scenes, the KEDA scaler is the component that responds to that queue depth and triggers ACA job executions. Concurrency and parallelism end up being a combination of your workflow’s matrix/strategy choices in GitHub, the KEDA scaling parameters (min/max executions per polling interval), and the container resources (CPU/memory) and job settings like `parallelism` and `replicaCompletionCount` if you ever decide to run multiple containers per execution. Most of the time, the simple 1:1 mapping between a job execution and a single runner container works well.

### 5) KEDA scaling behavior

The `github-runner` scaler periodically queries the GitHub API to estimate queued work for the scope and labels you configured. Whenever the queue length meets or exceeds `targetWorkflowQueueLength`, KEDA triggers job executions up to `maxExecutions` for that polling interval. There are a couple of practical tuning knobs here. A lower `pollingInterval` reduces start latency at the cost of more API calls, so it is worth enabling ETags (`enableEtags=true`) to ease rate‑limit pressure. Narrowing the scope with explicit `repos` lists and well‑chosen labels both improves responsiveness and avoids over‑scaling generic runners for jobs that really need specialized images. Finally, remember that PATs have lower rate limits than GitHub Apps, so if you expect high throughput or many repositories, GitHub App auth is usually the better choice. For full details, see the KEDA scaler docs at https://keda.sh/docs/latest/scalers/github-runner/.

## Security, identity, and secrets

This design leans hard on managed identities and GitHub Apps so you do not have to scatter long‑lived secrets across scripts and parameter files. For registry access, the job pulls from ACR using a managed identity rather than a username and password: you assign `AcrPull` to the job’s user‑assigned identity and configure the registry `identity` as either the UAMI resource ID or `system` for system‑assigned identity (see https://learn.microsoft.com/azure/container-apps/containers?tabs=bicep#managed-identity-with-azure-container-registry).

On the GitHub side, the recommended path is to use a GitHub App, not a PAT. The environment’s `GH_APP_ID` and `GH_APP_INSTALLATION_ID` variables and the `GH_APP_PRIVATE_KEY` secret supply the app metadata and PEM key to the bootstrap workflow (per https://docs.github.com/actions/security-guides/using-secrets-in-github-actions). The workflow passes these values into the Bicep deployment, which persists the key in Azure Key Vault and grants the job identity `Key Vault Secrets User`. At runtime the runner and scaler can mint JWTs and installation tokens on demand (see https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets?tabs=arm-bicep and https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app). A minimal‑scope PAT remains supported as a fallback if you need it, but the intent is that most deployments never have to rely on it.

Scope selection matters as well. When you use a personal GitHub user (for example `broberts23`) as `githubOwner`, you should set `githubRunnerScope` to `repo` so the scaler and runner use `/repos/{owner}/{repo}` endpoints and the GitHub App only needs **Repository → Administration (Read & write)** on that repo. Reserve `githubRunnerScope: "org"` for situations where `githubOwner` is a real GitHub Organization, `/orgs/{org}` and `/orgs/{org}/repos` resolve successfully, and the app is installed on that organization with **Organization → Self-hosted runners (Read & write)**.

GitHub’s own REST reference is very explicit about what permissions are required for the various registration endpoints, which is summarized in the table below.

GitHub App permission matrix:

| Runner scope | Registration endpoint                                               | Required permission                                   |
| ------------ | ------------------------------------------------------------------- | ----------------------------------------------------- |
| `repo`       | `POST /repos/{owner}/{repo}/actions/runners/registration-token`     | Repository → **Administration (Read & write)**        |
| `org`        | `POST /orgs/{org}/actions/runners/registration-token`               | Organization → **Self-hosted runners (Read & write)** |
| `ent`        | `POST /enterprises/{enterprise}/actions/runners/registration-token` | Enterprise-level **Self-hosted runners** permission   |

These requirements come directly from the GitHub REST reference (see https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-a-registration-token-for-a-repository and https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-a-registration-token-for-an-organization). If the installation token lacks the relevant permission or repository access, the API returns `403 Resource not accessible by integration` per https://docs.github.com/en/rest/using-the-rest-api/troubleshooting#resource-not-accessible. Whenever you change app permissions or repository selections, it is worth re‑authorizing the installation so GitHub issues tokens with the expanded scope.

Beyond these specifics, the security posture is intentionally conservative: there are no long‑lived runner nodes (job executions are ephemeral, which reduces standing privilege and image drift), images are versioned and tags pinned, and secrets never live directly in parameter files or scripts. Instead, you retrieve sensitive values locally with SecretManagement or GitHub environments, let the deployment write them into Key Vault, and rely on secret references at runtime while being careful not to log secret material.

## Observability and operations

Once everything is deployed, most of your day‑to‑day operational work happens in Log Analytics and through the Container Apps APIs. Container stdout/stderr and scale events flow into the workspace automatically, so you can use Kusto queries to investigate runner bootstrap behavior and job logs. For a quick health check, `az containerapp job execution list` (or the Azure portal) shows you recent executions and statuses, and you can drill into specific runs when something fails.

Because the pattern uses event‑driven jobs, cost tends to track actual work closely—you pay while containers run and effectively nothing when there is no queued work. It is still worth keeping an eye on image hygiene: keep runner images minimal, refresh them regularly, and, if your builds need large toolchains, consider splitting into multiple label‑targeted images so not every job has to carry every dependency.

## Troubleshooting GitHub App 403 responses

If you ever run into `403 Resource not accessible by integration` responses from GitHub, the logs from `github-actions-runner/entrypoint.sh` are your first stop. The script logs both the HTTP status code and response body whenever GitHub rejects a request, so instead of a silent `curl` failure you will see something like `GitHub API POST ...registration-token failed (403): {"message":"Resource not accessible by integration"...}` along with whatever additional detail GitHub provides.

From there, work through a short checklist. First, confirm that the GitHub App’s permissions align with the `githubRunnerScope` you chose, using the permission matrix above as a guide and the REST docs for the exact endpoint you are calling (for example https://docs.github.com/en/rest/actions/self-hosted-runners?apiVersion=2022-11-28#create-a-registration-token-for-a-repository). Next, look at the `X-Accepted-GitHub-Permissions` response header; GitHub includes it when a permission is missing, and it tells you exactly what the API expected (see https://docs.github.com/en/rest/using-the-rest-api/troubleshooting#resource-not-accessible). Finally, open the GitHub App installation page and make sure every repository listed in `githubRunnerRepositories` is actually selected (or that you have chosen “All repositories”). After changing either permissions or repository selection, re‑authorize the installation so new tokens pick up the broadened scope.

Finally, verify that the `GH_APP_PRIVATE_KEY` secret contains the full PEM content. When looking at the secret in Azure Key Vault, it should be in the form:

```
-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n
```

Another tip is to use Get-AzSecret to pull the secret locally and confirm it has the expected format:

```powershell
az keyvault secret show \
  --vault-name <kv-name> \
  --name github-app-key \
  --query value \
  --output tsv > /tmp/app-key.txt

cat /tmp/app-key.txt
```

Then use openssl to validate the PEM:

```bash
openssl rsa -in ./github-app-private-key.pem -check
```


## Implementation details in this repo

The composed `infra/main.bicep` surface area is intentionally small but flexible. You tell it which image to run and how much CPU/memory it should have, provide GitHub details like `githubOwner`, `githubRepo`, and `runnerLabels`, and then choose your scaling behavior with parameters such as `minExecutions`, `maxExecutions`, `pollingInterval`, and `targetWorkflowQueueLength`. Additional knobs control how the scaler talks to GitHub (`githubApiUrl`, `githubRunnerScope`, `githubRunnerRepositories`, `disableDefaultRunnerLabels`, `matchUnlabeledRunnerJobs`, `enableGithubEtags`, and `additionalScaleRuleAuth`) and how the job authenticates to Azure resources (`acrName`, `userAssignedIdentityId`).

The `containerapps/githubRunnerJob.bicep` module takes those inputs and renders the actual job resource, including the `rules: [ { type: 'github-runner', metadata, auth } ]` block for KEDA. That split keeps the job specification clean and auditable while still giving you the levers you need at deployment time.

## GitHub Actions infrastructure bootstrap workflow

The repository includes `.github/workflows/bootstrap-infra.yml`, a GitHub Actions pipeline that builds the runner image and deploys the Bicep template end to end.

High-level behavior:

- **Trigger and inputs**: The workflow runs on `workflow_dispatch` with inputs for `environment` (`dev` or `prod`), an optional `imageTagSuffix`, and an optional `parametersFile` override.
- **Environment resolution**: The `Resolve deployment configuration` step maps the logical environment to concrete values:
  - `dev` → `rg-github-runner-dev`, `eastus`, `ghrunnerdevacr`, parameters file `project-github-runner/infra/parameters.dev.json`.
  - `prod` → `rg-github-runner-prod`, `eastus`, `ghrunnerprodacr`, parameters file `project-github-runner/infra/parameters.prod.json`.
  - If `parametersFile` is provided, it overrides the default; the step fails fast if the file does not exist.
- **Image tagging**: The same step computes a container image tag of the form `<acrName>.azurecr.io/github-actions-runner:<suffix>`, where `<suffix>` defaults to `v${{ github.run_number }}` unless overridden by `imageTagSuffix`.

Deployment sequence in the job:

1. **Checkout**: `actions/checkout@v4` pulls the repo so Docker and Bicep can see `project-github-runner`.
2. **Azure login (OIDC)**: [`azure/login@v2`](https://github.com/Azure/login) authenticates to Azure using federated credentials, driven by `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID` in GitHub secrets. This follows the guidance in [Deploy Bicep with GitHub Actions](https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-github-actions).
3. **Resource group creation**: [`azure/cli@v2`](https://github.com/Azure/cli) runs `az group create` to ensure the target resource group exists (see [`az group create`](https://learn.microsoft.com/cli/azure/group?view=azure-cli-latest#az-group-create)).
4. **Prepare infrastructure deployment**: An initial `azure/bicep-deploy@v2` step (`Deploy infrastructure (Bicep - prepare)`) runs against `infra/main.bicep` with the resolved parameters file and overrides for:
   - `containerImage`: the computed ACR image tag.
   - `acrName`: the resolved registry name.
   - `githubAppApplicationId`, `githubAppInstallationId`, `githubAppPrivateKey`: sourced from environment variables `GH_APP_ID`, `GH_APP_INSTALLATION_ID`, and secret `GH_APP_PRIVATE_KEY` respectively.
     This step is `continue-on-error: true` so the image build can proceed even if the first deployment attempt fails (for example, on a cold start).
5. **ACR login**: A plain `az acr login` signs the Docker client into the target ACR so the subsequent build can push the image.
6. **Build and push image**: [`docker/setup-buildx-action@v3`](https://github.com/docker/setup-buildx-action) prepares Buildx, and [`docker/build-push-action@v6`](https://github.com/docker/build-push-action#usage) builds `project-github-runner/Dockerfile.github` with context `project-github-runner` and pushes it to the tag computed earlier.
7. **Finalize infrastructure deployment**: A second `azure/bicep-deploy@v2` step reruns the deployment of `infra/main.bicep` with the same parameters file and overrides, guaranteeing that the Container Apps job uses the freshly pushed image tag.
8. **Summary**: The final step appends a summary to the GitHub Actions job log containing the environment, resource group, image tag, and the Container Apps job and environment IDs returned by the Bicep deployment.

Required GitHub configuration for the workflow:

- **Azure OIDC**: Secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` for federated authentication.
- **GitHub App metadata**: Environment variables `GH_APP_ID` and `GH_APP_INSTALLATION_ID` (environment-level `vars` in GitHub) supplying the GitHub App ID and installation ID; see [Authenticating as a GitHub App installation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation#generating-an-installation-access-token) for ways to discover the installation ID.
- **GitHub App private key**: Environment secret `GH_APP_PRIVATE_KEY`, generated from the GitHub App settings per [Managing private keys for GitHub Apps](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/managing-private-keys-for-github-apps). The Bicep deployment writes this value into Azure Key Vault so the job and KEDA scaler can authenticate without embedding secrets in templates.
- **Optional PAT**: A repository secret such as `GITHUB_PAT_RUNNER` remains supported for PAT-based deployments when you do not want to (or cannot) use a GitHub App.

When dispatching manually you can override the parameters file (for example `project-github-runner/infra/parameters.prod.json` for a production deployment) or supply a custom image tag suffix; the `Resolve deployment configuration` step ensures the final image tag and parameter file are consistent with the chosen environment.

## Example flow (putting it all together)

In a typical run, you deploy the Bicep template to your resource group with the parameters that describe your environment, GitHub owner/repository, and scaling preferences. Once the deployment completes, you confirm that the Container Apps environment and job exist and that the job template has the expected environment variables and secret wiring. You then point a GitHub workflow at `runs-on: [self-hosted, azure-container-apps, <your-labels>]`, matching `<your-labels>` to what you configured on the runner.

From there, the experience is pleasantly boring: you queue a workflow, KEDA notices the queued job within roughly `pollingInterval` seconds, and ACA starts the necessary job executions. Runners register, process their assigned work, and exit. When there is no more work in the queue, subsequent polls result in zero executions and the job scales down to zero again.

## Troubleshooting tips

- No job executions: Verify scaler metadata (owner/scope/repos), confirm the GitHub App secret name in `scaleRuleAuth` aligns with the Key Vault-backed secretRef, and ensure the job identity retains `Key Vault Secrets User`. Labels in your workflow must match the runner configuration.
- Image pull errors: Check ACR `AcrPull` assignment and that the `registries.identity` matches the enabled identity. Confirm ACR “authentication as ARM” status when using MI pulls.
- Rate limiting: Reduce API calls via more selective `repos`, `enableEtags`, or switch to GitHub App auth.
- Runner not registering: Confirm the container env includes `REGISTRATION_TOKEN_API_URL`, repository URL, `APP_ID`, and `APP_INSTALLATION_ID`, and that the Key Vault reference can resolve the private key (review logs for secret retrieval errors). If you revert to PAT fallback, regenerate the PAT and verify network egress to `https://api.github.com`.

## Conclusion

This project now represents a complete, opinionated pattern for running GitHub Actions workloads on Azure Container Apps jobs:

- **Infrastructure as code**: A single composed Bicep template (`infra/main.bicep`) stands up the Container Apps environment, job, virtual network, Log Analytics, ACR, managed identities, and KEDA `github-runner` scaler with environment-specific parameter files.
- **Hardened runner image**: `Dockerfile.github` builds on the official GitHub Actions runner image and layers in PowerShell 7.4, Azure CLI, Bicep, and Az/Microsoft.Graph modules so typical cloud build/test/deploy pipelines work out of the box.
- **GitHub App–first authentication**: The default path uses a GitHub App with narrowly scoped permissions, Key Vault–backed private key storage, and a KEDA scaler that authenticates via the same app; PAT-based auth remains available as a fallback.
- **Automated bootstrap workflow**: `.github/workflows/bootstrap-infra.yml` ties everything together—building and pushing the runner image, deploying the Bicep template with the correct tag and GitHub App metadata, and emitting IDs you can plug into downstream automation.
- **Ephemeral, scalable execution**: Runners are created per job execution, register just long enough to process a workflow, and then exit. KEDA scales executions up and down based on queue depth so you only pay for active work while avoiding long-lived build agents.

Taken together, the templates, scripts, and workflows in this repository give you a reusable starting point for production-ready self‑hosted runners: auditable, parameterized, and easy to adapt to additional environments, images, or GitHub organizations as your CI footprint grows.

## References

- Jobs in Azure Container Apps: https://learn.microsoft.com/azure/container-apps/jobs?tabs=azure-cli
- Containers in Azure Container Apps (registries, MI): https://learn.microsoft.com/azure/container-apps/containers?tabs=bicep
- Azure Container Apps environments (logs): https://learn.microsoft.com/azure/container-apps/environment?tabs=bicep#logs
- Monitor logs in Azure Container Apps with Log Analytics: https://learn.microsoft.com/azure/container-apps/log-monitoring?tabs=bash
- View log streams in Azure Container Apps: https://learn.microsoft.com/azure/container-apps/log-streaming?tabs=bash
- Tutorial: GitHub Actions runners on ACA jobs: https://learn.microsoft.com/azure/container-apps/tutorial-ci-cd-runners-jobs?tabs=bicep&pivots=container-apps-jobs-self-hosted-ci-cd-github-actions
- KEDA GitHub runner scaler: https://keda.sh/docs/latest/scalers/github-runner/
