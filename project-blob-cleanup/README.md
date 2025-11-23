# Azure Blob Storage Lifecycle Management Policy

Bicep-based infrastructure-as-code (IaC) for deploying Azure Blob Storage Lifecycle Management Policies that automatically delete blobs (and snapshots) older than a retention window (default 7 days) across configurable containers.

Reference: [Azure Blob Storage Lifecycle Management](https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-overview)

## Overview

This project uses native Azure Storage lifecycle policies—no custom code or Function Apps required. The policy runs automatically within the Azure Storage service, applying deletion rules based on blob metadata (`LastModified` for base blobs, creation time for snapshots).

## Features

- **Infrastructure as Code**: Bicep templates for repeatable, auditable deployments
- **Multi-Environment Support**: Separate parameter files for dev, test, and prod
- **Consolidated Rule**: Single lifecycle rule with multiple container prefixes (stays under Azure rule quotas)
- **Snapshot Cleanup**: Automatically removes snapshots alongside base blobs
- **Zero Maintenance**: Service-managed execution—no servers, no scaling concerns
- **Existing Storage Account**: Designed to configure existing accounts without re-provisioning

## Project Structure

```
project-blob-cleanup/
├── infra/
│   ├── main.bicep                  # Main deployment template
│   ├── modules/
│   │   └── lifecyclePolicy.bicep   # Lifecycle policy module
│   ├── parameters.dev.json         # Dev environment config
│   ├── parameters.test.json        # Test environment config
│   └── parameters.prod.json        # Prod environment config
├── scripts/
│   └── Seed-StorageContainers.ps1  # Create test blobs with date patterns
├── docs/
│   └── blog.md                     # Deep dive on lifecycle policies
└── README.md
```

## Configuration

Each environment parameter file (`parameters.{env}.json`) specifies:

| Parameter            | Description                                   | Example                |
| -------------------- | --------------------------------------------- | ---------------------- |
| `storageAccountName` | Name of the existing Storage Account          | `stprodblobcleanup001` |
| `containerPrefixes`  | Array of container name prefixes to target    | `["audit", "samples"]` |
| `retentionDays`      | Days after modification before deleting blobs | `7`                    |
| `enabled`            | Enable or disable the lifecycle rule          | `true`                 |

The `containerPrefixes` array is consolidated into a single lifecycle rule's `prefixMatch` filter, keeping the policy lean and under Azure's rule count limits.

## Deployment

### Prerequisites

- Azure CLI or PowerShell Az module installed
- Existing Storage Account in target Resource Group
- Contributor or Storage Account Contributor role on the subscription/resource group

Reference: [Connect-AzAccount](https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest)

### Deploy via PowerShell

```powershell
# Authenticate
Connect-AzAccount

# Variables
$resourceGroup = "rg-blobcleanup-prod"
$location = "eastus"
$environment = "prod"  # or "dev", "test"

# Deploy the lifecycle policy
New-AzResourceGroupDeployment `
  -ResourceGroupName $resourceGroup `
  -TemplateFile ./infra/main.bicep `
  -TemplateParameterFile ./infra/parameters.$environment.json `
  -Verbose
```

Reference: [New-AzResourceGroupDeployment](https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest)

### Deploy via Azure CLI

```bash
# Authenticate
az login

# Variables
RESOURCE_GROUP="rg-blobcleanup-prod"
LOCATION="eastus"
ENVIRONMENT="prod"

# Deploy
az deployment group create \
  --resource-group $RESOURCE_GROUP \
  --template-file ./infra/main.bicep \
  --parameters ./infra/parameters.$ENVIRONMENT.json
```

Reference: [az deployment group create](https://learn.microsoft.com/cli/azure/deployment/group#az-deployment-group-create)

## Seeding Test Data

Use the PowerShell seeding script to populate containers with timestamped blobs representing days in the past and future. This helps visualize which blobs would be deleted by the policy.

### Example Run

```powershell
# Create blobs for 12 days in the past and 2 days in the future
./scripts/Seed-StorageContainers.ps1 `
  -StorageAccountName "stdevblobcleanup001" `
  -ResourceGroup "rg-blobcleanup-dev" `
  -PastDays 12 `
  -FutureDays 2
```

The script creates virtual directory structures like:

- `imports/signin/entra/20251110000000-1.json`
- `exports/signin/activedirectory/20251115120000-2.json`
- `audit/logs/system/20251123180000-1.json`

## How Lifecycle Policies Work

Azure Storage evaluates lifecycle rules periodically (timing is service-managed). Blobs matching the filter criteria (`blobTypes`, `prefixMatch`) have their `LastModified` timestamp compared against the `daysAfterModificationGreaterThan` threshold. Snapshots use their creation time with `daysAfterCreationGreaterThan`.

**Important**: Unlike custom code approaches, lifecycle policies:

- Cannot parse filename-embedded timestamps (only use blob metadata)
- Do not provide per-run deletion counts in logs (use Storage Analytics or independent monitoring)
- Execute on an internal schedule (not at a precise time you control)

For detailed policy mechanics and advanced scenarios, see `docs/blog.md`.

## Monitoring

Lifecycle policy executions are not logged to Application Insights. To track deletions:

1. Enable [Storage Analytics Logging](https://learn.microsoft.com/azure/storage/common/storage-analytics-logging)
2. Query `StorageBlobLogs` table in Log Analytics (if diagnostic settings route to workspace)
3. Use Azure Monitor alerts on container item count metrics

## Customization

### Change Retention Period

Edit `retentionDays` in the parameter file:

```json
"retentionDays": {
  "value": 14
}
```

Redeploy to apply.

### Add More Containers

Append to `containerPrefixes` array:

```json
"containerPrefixes": {
  "value": [
    "signin",
    "audit",
    "logs",
    "newcontainer"
  ]
}
```

### Disable Policy Temporarily

Set `enabled` to `false` in parameter file and redeploy.

## Advanced Scenarios

The module `infra/modules/lifecyclePolicy.bicep` exposes parameters for:

- Separate base blob and snapshot retention periods
- Toggling rule enabled state

For more complex policies (tiering to Cool/Archive before deletion, version cleanup), extend the module's `actions` block. See `docs/blog.md` for examples.

## Bicep Best Practices Applied

Reference: [Bicep Best Practices](https://learn.microsoft.com/azure/azure-resource-manager/bicep/best-practices)

- ✅ **Modular design**: Lifecycle policy logic isolated in `modules/lifecyclePolicy.bicep`
- ✅ **Parameter files per environment**: Separate dev/test/prod configurations
- ✅ **Existing resource references**: Uses `existing` keyword for Storage Account
- ✅ **Validation decorators**: `@minValue`/`@maxValue` on retention parameters
- ✅ **Output exposure**: Key values returned for pipeline integration

## Contributing

When adding new features:

1. Update the module with new parameters/actions
2. Document changes in `docs/blog.md`
3. Add new parameter files if introducing environments
4. Test deployments in dev before promoting to prod

## References

- [Azure Blob Storage Lifecycle Management](https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-overview)
- [Bicep Documentation](https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview)
- [Storage Account Management Policies API](https://learn.microsoft.com/azure/templates/microsoft.storage/storageaccounts/managementpolicies)
- [Connect-AzAccount](https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest)
