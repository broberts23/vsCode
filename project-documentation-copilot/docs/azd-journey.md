# End-to-End azd Journey

Step-by-step commands for developing, testing, and deploying the Documentation Copilot using the Azure Developer CLI and Foundry extensions.

Adapted from `project-identity-security-copilot-v2` OUTLINE.md §9.

## Prerequisites (one-time per machine)

```pwsh
# Python 3.13+
python --version

# Azure CLI
az login

# Azure Developer CLI
azd version
azd ext install microsoft.foundry
azd ext install azure.ai.skills
```

## Step 1 — Scaffold the Agent

```pwsh
azd ai agent init -m "https://github.com/microsoft-foundry/foundry-samples/blob/main/samples/python/hosted-agents/agent-framework/responses/01-basic/agent.manifest.yaml"
```

After init completes:

```pwsh
azd env set AZURE_SUBSCRIPTION_ID <subscription-id>
azd env set AZURE_LOCATION eastus2
```

Replace the generated `main.py` with `agents/documentation-copilot/main.py`.

## Step 2 — Provision Azure Resources

```pwsh
azd provision
```

Creates: resource group, Foundry project, deepseek-v4-flash deployment, Log Analytics, managed identities.

## Step 3 — Upload Skills

```pwsh
azd ai skill create wiki-authoring --file ./skills/wiki-authoring/SKILL.md --no-prompt -o json
azd ai skill create code-analysis --file ./skills/code-analysis/SKILL.md --no-prompt -o json

azd ai skill list -o table
```

## Step 4 — Publish MCP Toolbox

```pwsh
azd provision
azd ai toolbox publish
```

## Step 5 — Test Locally

```pwsh
# Terminal 1: Start the agent
azd ai agent run --no-inspector

# Terminal 2: Send a test prompt
azd ai agent invoke --local "update the wiki for load_config function"
```

Or with curl:

```pwsh
curl -sS -H "Content-Type: application/json" -X POST http://localhost:8088/responses -d '{"input": "create a new wiki for DataService", "stream": false}'
```

## Step 6 — Deploy to Foundry

```pwsh
azd deploy
```

Expected output:

```
  Done: Deploying service documentation-copilot
  - Agent endpoint: https://ai-account-<name>.services.ai.azure.com/api/projects/<project>/agents/documentation-copilot/versions/1
```

## Step 7 — Poll Agent Status

```pwsh
azd ai agent show
```

Wait for `Status: active`.

## Step 8 — Invoke Deployed Agent

```pwsh
azd ai agent invoke "update the wiki for MyFunction to capture the latest changes"
azd ai agent invoke "create a new wiki for AuthService class"
```

## Step 9 — Verify in Portal

1. Open https://ai.azure.com
2. Navigate to project → Build → Agents
3. Select `documentation-copilot` → Open in playground
4. Verify wiki pages in Azure DevOps Wiki

## Step 10 — Tear Down

```pwsh
azd down
```

---

## Failure Modes

| Error | Resolution |
|---|---|---|
| `SubscriptionNotRegistered` | `az provider register -n Microsoft.CognitiveServices` |
| `AuthorizationFailed` | Request Contributor at resource group scope |
| `AuthenticationError` | `azd auth logout && azd auth login` |
| deepseek-v4-flash not found | Verify model is available in selected region (Global Standard) |
| Agent `failed` | Check `error.message` — typically pip resolution issue |
| 401 from DevOps API | Verify `AZURE_DEVOPS_PAT` is set and has Wiki scope |
