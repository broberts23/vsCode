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

This repository includes Bicep modules and a composed template that deploy:

- A Log Analytics workspace for Container Apps logging.
- A Container Apps environment configured to push logs to the workspace.
- An Azure Container Registry (ACR) that the template provisions and assigns `AcrPull` to the runner job’s managed identity.
- A virtual network, delegated subnet, and network security group that provide private connectivity for the environment per [Custom virtual networks for Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/custom-virtual-networks?tabs=bicep).
- An Azure Container Apps event‑driven Job that runs the GitHub Actions runner image, registers with your repo/org, and exits when the workflow completes.
- A KEDA github‑runner scaler that watches your GitHub queue and triggers job executions accordingly.
- A container build scaffold (`Dockerfile.github`, `github-actions-runner/entrypoint.sh`, and `scripts/Build-GitHubRunnerImage.ps1`) that packages the latest upstream runner release (`v2.329.0` at https://github.com/actions/runner/releases/tag/v2.329.0) with minimal dependencies.

Outputs include resource IDs, environment ID, and registry information for downstream automation.

## Repository structure (relevant parts)

```
project-github-runner/
  infra/
    main.bicep                      # Composes environment, ACR, and the job
    containerapps/
      logAnalytics.bicep            # Log Analytics workspace
      managedEnvironment.bicep      # Container Apps environment
      containerRegistry.bicep       # ACR with AcrPull assignment
      githubRunnerJob.bicep         # Event-driven job + KEDA scaler wiring
    network/
      vnet.bicep                    # Virtual network, subnet delegation, and NSG for ACA
  blog.md                           # This article
```

## Architecture overview

Components and responsibilities:

- Log & Observability: An Azure Monitor Log Analytics workspace captures container logs, scale events, and job execution history at the environment level. See https://learn.microsoft.com/azure/container-apps/environment?tabs=bicep#logs
- Compute Boundary: A Container Apps environment hosts the job. This is the secure network/logging boundary for your runners.
- Network Access: A dedicated virtual network and delegated subnet isolate the environment, while a network security group allows you to enforce egress controls or lock down ingress. See https://learn.microsoft.com/azure/container-apps/custom-virtual-networks?tabs=bicep.
- Image Supply: The runner image is pulled from ACR (or another registry). Use managed identity authentication to ACR where possible. See https://learn.microsoft.com/azure/container-apps/containers?tabs=bicep#managed-identity-with-azure-container-registry
- Identity: Optionally attach a user‑assigned managed identity to the job. Grant AcrPull on ACR to this identity.
- Secrets: A GitHub PAT (or GitHub App key) is stored as a Container Apps secret. The container uses it to fetch a short‑lived registration token and register the runner.
- Scaling: A KEDA scaler queries GitHub for queued jobs using the PAT/App credentials. When the queue length exceeds your target, KEDA triggers ACA job executions. Each execution runs one ephemeral runner container that exits after the workflow completes.

Flow:

1) GitHub workflow queues a job targeting your self‑hosted labels.
2) KEDA scaler polls the GitHub API and detects queued work.
3) ACA starts N job executions (bounded by min/max per interval). Each execution creates a pod with the runner container.
4) The runner registers with GitHub, picks up the job, executes steps, and exits.
5) ACA marks the execution complete. With no pending work, future polls result in zero executions.

## Demo GitHub Actions pipeline

To make the experience tangible, the repository includes `.github/workflows/demo-self-hosted-runner.yml`. You can dispatch the workflow from the **Actions** tab and it will schedule nine parallel jobs using a matrix strategy:

- Each matrix instance targets the `self-hosted` and `azure-container-apps` labels, ensuring jobs land on the Container Apps runners created by the Bicep deployment.
- `max-parallel: 9` allows all jobs to execute concurrently, forcing the KEDA scaler to scale the job to nine containers (bounded by `maxExecutions`).
- Steps inside each job record the runner host name, verify PowerShell 7.4, and simulate a short workload to keep the container running long enough for scale observation.

When you trigger the workflow:

1. GitHub places nine jobs in the queue (`RUNNER_LABELS` must match the workflow).
2. The scaler detects the queue depth (`targetWorkflowQueueLength` defaults to `1`) and schedules up to nine executions within the Container Apps environment.
3. Each execution registers as an ephemeral runner, processes its portion of the matrix, and exits.
4. You can monitor progress with `az containerapp job execution list --name <jobName> --resource-group <rg>` (https://learn.microsoft.com/cli/azure/containerapp/job/execution) and inspect job output through Log Analytics queries.

This pipeline provides a repeatable way to validate scale-out, confirm network access, and capture telemetry before onboarding production workloads.

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

## How GitHub runners work in ACA jobs (end‑to‑end)

### 1) Resource creation (Bicep)

- `logAnalytics.bicep` provisions a workspace (retention configurable). Outputs: `customerId`, `workspaceId`.
- `managedEnvironment.bicep` creates the Container Apps environment and connects it to Log Analytics (`appLogsConfiguration`).
- `containerRegistry.bicep` creates ACR and assigns `AcrPull` to a supplied principal (for example, a user‑assigned managed identity).
- `githubRunnerJob.bicep` defines an event‑driven Job resource (`Microsoft.App/jobs`) with:
  - Container image, CPU/memory, and environment variables for runner bootstrap.
  - Secrets: a PAT (or App key) exposed to the container via secretRef.
  - Registries: server + identity for managed identity pulls.
  - KEDA scale block: scaler type `github-runner` with metadata (owner, scope, repos, labels, target queue length) and auth (PAT/App key).

The composed `infra/main.bicep` stitches these modules together and normalizes inputs like URLs and labels. It exposes parameters for tuning scale behavior (min/max executions, polling interval, targetWorkflowQueueLength).

### 2) Deploying the job

A typical deployment flow:

- Create a resource group and deploy `infra/main.bicep` with parameters for:
  - `githubOwner` and `githubRepo` (or org scope).
  - `containerImage` for your runner (for example, ghcr.io or ACR path).
  - `githubPatSecretValue` as a secure parameter (or switch to GitHub App auth with application/installation IDs and PEM secret).
  - Scale parameters: `minExecutions`, `maxExecutions`, `pollingInterval`, `targetWorkflowQueueLength`.
  - Identity parameters for ACR managed pulls.
- The outputs include the job resource ID and environment ID; logs flow to Log Analytics automatically.

The KEDA scaler requires the PAT or GitHub App parameters and correct metadata:

- `owner`: org/user.
- `runnerScope`: `repo` | `org` | `ent`.
- `repos`: comma‑separated list when using `repo` scope.
- `labels`: optional, to target specific runner labels.
- `targetWorkflowQueueLength`: typically 1.
- `pollingInterval`: default 30 seconds; adjust for rate/capacity trade‑offs.

Reference: https://keda.sh/docs/latest/scalers/github-runner/

### 3) Runner bootstrap and registration with GitHub

When a job execution starts, ACA launches the runner container with environment variables and secrets provided by Bicep. The runner process performs the following steps:

1) Exchanges the PAT (secret) for a short‑lived registration token via GitHub REST: `POST /repos/{owner}/{repo}/actions/runners/registration-token` (or org/ent variant). The job template includes `REGISTRATION_TOKEN_API_URL` and `GH_URL`/repo for clarity.
2) Configures the runner with your labels and repository/organization context.
3) Registers the runner; it shows up as an online self‑hosted runner in GitHub.
4) Waits for a workflow job assignment; when received, executes all steps.
5) On completion, the container exits. Ephemeral patterns typically remove the runner registration automatically on shutdown.

This lifecycle ensures no idle, permanently registered VMs—each execution is purpose‑built and disposed.

### 4) Using the runners in GitHub Actions

In your workflow YAML:

- Target self‑hosted runners with the appropriate labels:

```yaml
runs-on: [self-hosted, azure-container-apps]
```

- Add repo or org‑specific labels (e.g., `dotnet`, `arm64`, `build-tools`) to steer jobs to the correct image or toolchain.
- Jobs queue in GitHub until a matching self‑hosted runner comes online (which the KEDA scaler triggers via ACA job executions).
- Concurrency and parallelism are governed by:
  - Your workflow matrix/strategy in GitHub.
  - KEDA scaling parameters (min/max executions per polling interval).
  - Container resources (CPU/Memory) and job `parallelism`/`replicaCompletionCount` if you choose to run multiple containers per execution (most runner patterns use 1:1 execution:container).

### 5) KEDA scaling behavior

The `github-runner` scaler periodically queries the GitHub API to estimate queued work for the specified scope and labels. If the queue length ≥ `targetWorkflowQueueLength`, KEDA triggers job executions up to `maxExecutions` per poll. Key considerations:

- `pollingInterval`: Lower values reduce start latency but increase API calls; enable ETags (`enableEtags=true`) to mitigate rate‑limit impact.
- Scope & filters: Prefer `repos` lists and labels to reduce API breadth and improve responsiveness.
- Labels: Use precise labels to avoid over‑scaling generic runners for jobs that need specialized images.
- Rate limits: PAT limits are lower than GitHub App limits; consider GitHub App auth for higher throughput.

Reference: https://keda.sh/docs/latest/scalers/github-runner/

## Security, identity, and secrets

- Registry auth: Use managed identities to pull from ACR. Assign `AcrPull` to the job’s user‑assigned identity and configure the registry `identity` as either the UAMI resource ID or `system` for system‑assigned identity. Docs: https://learn.microsoft.com/azure/container-apps/containers?tabs=bicep#managed-identity-with-azure-container-registry
- GitHub auth: Start with a PAT for simplicity; rotate frequently. For scale or security, prefer GitHub App authentication (supply `applicationId`, `installationId`, and the PEM key via a secret).
- No long‑lived runner nodes: Ephemeral job executions mitigate standing privilege and drift in base images. Version images and pin tags.
- Secrets handling: Provide the PAT/App key via ACA secrets, not environment variables with literal values. Avoid logging secret values.

## Observability and operations

- Logs: Container stdout/stderr and scale events flow to Log Analytics from the environment. Use Kusto queries to investigate runner bootstrap and job logs.
- Health: Use `az containerapp job execution list` (or portal) to inspect recent executions and statuses.
- Cost: With event‑driven jobs, you pay only while containers run. Idle time is effectively zero when there’s no queued work.
- Image hygiene: Keep runner images minimal and regularly updated. If builds require large toolchains, consider multiple label‑targeted images to limit bloat.

## Implementation details in this repo

The composed `infra/main.bicep` exposes these key parameters (non‑exhaustive):

- Image & resources: `containerImage`, `containerCpu`, `containerMemory`.
- GitHub details: `githubOwner`, `githubRepo`, `runnerLabels`.
- Secrets: `githubPatSecretName`, `githubPatSecretValue`.
- Scaling: `minExecutions`, `maxExecutions`, `pollingInterval`, `targetWorkflowQueueLength`.
- Scaler tuning: `githubApiUrl`, `githubRunnerScope`, `githubRunnerRepositories`, `disableDefaultRunnerLabels`, `matchUnlabeledRunnerJobs`, `enableGithubEtags`, GitHub App IDs, and `additionalScaleRuleAuth`.
- Registry & identity: `acrName`, `userAssignedIdentityId`.

The `containerapps/githubRunnerJob.bicep` module renders the `rules: [ { type: 'github-runner', metadata, auth } ]` block and builds metadata/auth maps from your parameters, keeping the job specification clean and auditable.

## GitHub Actions bootstrap workflow

The repository now includes `.github/workflows/bootstrap-infra.yml`, a GitHub Actions pipeline that automates the deployment sequence:

- Triggered by updates to infrastructure assets (Bicep files, runner Dockerfile) on `main` or by manual dispatch with environment-specific inputs.
- Resolves the resource group, Azure region, Azure Container Registry, and parameters file, then authenticates with OpenID Connect using [`azure/login@v2`](https://github.com/Azure/login) configured per [Deploy Bicep with GitHub Actions](https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-github-actions).
- Ensures the target resource group exists via `az group create` (see [`az group create`](https://learn.microsoft.com/cli/azure/group?view=azure-cli-latest#az-group-create)) and deploys `infra/main.bicep` using [`azure/bicep-deploy@v2`](https://github.com/Azure/bicep-deploy).
- Authenticates Docker to ACR (`az acr login`) and builds/pushes the runner image with [`docker/build-push-action@v6`](https://github.com/docker/build-push-action#usage), tagging images with a suffix such as `v${{ github.run_number }}`.
- Appends a job summary containing the image URL plus the container app job/environment IDs output from the template.

Required repository secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` (for OIDC auth) and `GITHUB_PAT_RUNNER` (passed to `githubPatSecretValue`). When dispatching manually you can supply a custom parameters file—e.g., `infra/parameters.prod.json`—to align with environment-specific naming, or adjust the case statement in the workflow to map additional environments.

## Example flow (putting it all together)

1) Deploy the Bicep template to your resource group with required parameters.
2) Confirm the Container Apps environment and Job exist; check the job template for env/secret wiring.
3) Update your GitHub workflow to use `runs-on: [self-hosted, azure-container-apps, <your-labels>]`.
4) Queue a workflow. Within ~`pollingInterval` seconds, KEDA should trigger job executions. Watch executions and logs in the portal or via CLI.
5) On completion, runners exit; when no work is queued, subsequent polls result in zero executions.

## Troubleshooting tips

- No job executions: Verify scaler metadata (owner/scope/repos) and the PAT/secret name mapping in `scaleRuleAuth`. Ensure labels match your workflow’s `runs-on`.
- Image pull errors: Check ACR `AcrPull` assignment and that the `registries.identity` matches the enabled identity. Confirm ACR “authentication as ARM” status when using MI pulls.
- Rate limiting: Reduce API calls via more selective `repos`, `enableEtags`, or switch to GitHub App auth.
- Runner not registering: Confirm the container env includes `REGISTRATION_TOKEN_API_URL`, repository URL, and that time/SSL are sane. Review container logs in Log Analytics.

## Conclusion

Self‑hosted GitHub runners on Azure Container Apps combine ephemeral, serverless execution with the control and proximity you need for real‑world CI workloads. With KEDA’s github‑runner scaler, capacity adapts automatically to your GitHub queue, while ACA jobs keep the runtime surface small and manageable. This repository’s Bicep templates and wiring give you an auditable, parameterized foundation to deploy, tune, and operate your fleet of on‑demand runners.

## References

- Jobs in Azure Container Apps: https://learn.microsoft.com/azure/container-apps/jobs?tabs=azure-cli
- Containers in Azure Container Apps (registries, MI): https://learn.microsoft.com/azure/container-apps/containers?tabs=bicep
- Azure Container Apps environments (logs): https://learn.microsoft.com/azure/container-apps/environment?tabs=bicep#logs
- Tutorial: GitHub Actions runners on ACA jobs: https://learn.microsoft.com/azure/container-apps/tutorial-ci-cd-runners-jobs?tabs=bicep&pivots=container-apps-jobs-self-hosted-ci-cd-github-actions
- KEDA GitHub runner scaler: https://keda.sh/docs/latest/scalers/github-runner/