# vsCode Solutions Monorepo

This repository contains several self-contained sample and utility projects focused on Azure, identity, and GitHub automation. Each subfolder under the root represents a distinct scenario.

## Project catalog

- `project-bicep-graph/`: End-to-end sample for deploying Azure infrastructure with Bicep and integrating with Microsoft Graph, including infra modules, C# Web API, and PowerShell-based smoke tests.
- `project-blob-cleanup/`: Storage hygiene sample that deploys Azure resources with Bicep and provides scripts/patterns for blob cleanup across environments.
- `project-conditional-access-ci/`: Guidance and scripts for building CI/CD workflows around Azure AD Conditional Access configuration, including export, validation, and deployment patterns.
- `project-entitlement-management/`: Samples and tooling related to Entra ID (Azure AD) entitlement management and access packages, aimed at automating governance scenarios.
- `project-functionapp-roles/`: Azure Functions + Easy Auth + Key Vault + LDAPS pattern for securely resetting on-prem AD passwords from a VNet-integrated Function App.
- `project-github-runner/`: Complete pattern for running ephemeral self-hosted GitHub Actions runners on Azure Container Apps jobs, with Bicep templates, runner image, KEDA scaling, and bootstrap workflows.
- `project-identity-governance-dashboard/`: Dashboard-focused project that surfaces identity governance signals (such as access reviews, assignments, and risky users) using Azure and Microsoft Graph.
- `project-jit-pim/`: Just-in-time Privileged Identity Management automation using Bicep and PowerShell, including sample workflows and tests for activating and auditing PIM assignments.
- `project-mcp/`: Model Context Protocol (MCP) related project(s) for experimenting with tooling/automation workflows.
- `project-servicenow/`: ServiceNow-focused automation/integration project(s) (workflows and scripts that bridge ITSM scenarios with Azure/identity automation).
- `project-workload-identity/`: Workload identity tooling for Entra ID and GitHub, including a PowerShell module and scripts that scan applications, report credential usage, and help migrate to federated credentials.

Each project folder contains its own README with deeper guidance, architecture notes, and usage examples. Start by opening the README in the project that matches the scenario you care about most, then explore the associated `infra/`, `scripts/`, and `src/` folders for implementation details.