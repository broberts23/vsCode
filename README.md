# vsCode Solutions Monorepo

This repository contains several self-contained sample and utility projects focused on Azure, identity (Microsoft Entra ID), and GitHub automation. Each subfolder under the root represents a distinct scenario, typically with some combination of `infra/` (Bicep), `scripts/` (PowerShell), `src/` (app code), `tests/`, and/or `workflows/`.

## Project catalog

- `project-bicep-graph/`: End-to-end sample for deploying Azure infrastructure with Bicep and integrating with Microsoft Graph, including infra modules, C# Web API, and PowerShell-based smoke tests.
- `project-blob-cleanup/`: Storage hygiene sample that deploys Azure resources with Bicep and provides scripts/patterns for blob cleanup across environments.
- `project-conditional-access-ci/`: Guidance and scripts for building CI/CD workflows around Microsoft Entra Conditional Access configuration, including export, validation, and deployment patterns.
- `project-entitlement-management/`: Samples and tooling related to Microsoft Entra entitlement management and access packages, aimed at automating governance scenarios.
- `project-eventgrid-partnerconfiguration/`: Receives Microsoft Graph change notifications via Azure Event Grid (partner events) and processes them with an Azure Function App (PowerShell), including queue buffering, idempotency/deduping, and subscription lifecycle handling.
- `project-functionapp-roles/`: Azure Functions + Easy Auth + Key Vault + LDAPS pattern for securely resetting on-prem AD passwords from a VNet-integrated Function App.
- `project-github-runner/`: Complete pattern for running ephemeral self-hosted GitHub Actions runners on Azure Container Apps jobs, with Bicep templates, runner image, KEDA scaling, and bootstrap workflows.
- `project-identity-governance-dashboard/`: Dashboard-focused project that surfaces identity governance signals (such as access reviews, assignments, and risky users) using Azure and Microsoft Graph.
- `project-jit-pim/`: Just-in-time Privileged Identity Management automation using Bicep and PowerShell, including sample workflows and tests for activating and auditing PIM assignments.
- `project-mcp/`: Reserved for Model Context Protocol (MCP) experimentation (currently an empty placeholder folder).
- `project-servicenow/`: ServiceNow-focused automation/integration project(s) (workflows and scripts that bridge ITSM scenarios with Azure/identity automation).
- `project-workload-identity/`: Workload identity tooling for Microsoft Entra ID and GitHub, including a PowerShell module and scripts that scan applications, report credential usage, and help migrate to federated credentials.

Most project folders contain their own README with deeper guidance, architecture notes, and usage examples. Start by opening the README in the project that matches the scenario you care about most, then explore the associated `infra/`, `scripts/`, and `src/` folders for implementation details.
