# Automating Blob Cleanup with Azure Storage Lifecycle Management Policies

Sometimes the solution you're building doesn't need another Function App, another timer trigger, or another piece of custom code to maintain. Azure Storage has a built-in lifecycle management engine that can handle age-based cleanup policies entirely within the service—no compute, no secrets, no runtime to monitor. This post walks through how lifecycle policies work, what you can do with them, and how to deploy them cleanly using Bicep.

Reference: [Azure Blob Storage Lifecycle Management](https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-overview)

## What Are Lifecycle Management Policies?

A lifecycle management policy is a JSON ruleset attached to a Storage Account that tells Azure, "Here's what I want you to do with blobs that match certain criteria." The Azure Storage service evaluates these rules once per day (timing is internal and service-managed) and applies actions like deleting old blobs, moving them to cooler storage tiers, or cleaning up versions and snapshots.

You define:

- **Filters**: Which blobs to target (by type, container prefix, blob name prefix)
- **Actions**: What to do with them (delete, tier to Cool/Archive, etc.)
- **Thresholds**: Time-based conditions (days since creation, modification, or last access)

The policy runs automatically, transparently, and scales with your data—no servers, no invocation logs to parse, no scaling concerns.

## Anatomy of a Lifecycle Rule

Here's the simplest possible rule: delete block blobs older than 7 days.

```json
{
  "rules": [
    {
      "name": "DeleteOldBlobs",
      "enabled": true,
      "type": "Lifecycle",
      "definition": {
        "filters": {
          "blobTypes": ["blockBlob"]
        },
        "actions": {
          "baseBlob": {
            "delete": {
              "daysAfterModificationGreaterThan": 7
            }
          }
        }
      }
    }
  ]
}
```

This rule:

- Targets all block blobs (`blobTypes`)
- Deletes base blobs (`baseBlob.delete`) if `LastModified` is more than 7 days ago
- Runs once daily (service-managed schedule)

## Filtering by Container

In production, you rarely want to apply a policy to every blob in the account. The `prefixMatch` filter lets you target specific containers or blob prefixes.

```json
"filters": {
  "blobTypes": ["blockBlob"],
  "prefixMatch": ["signin", "audit", "logs"]
}
```

This matches:

- `signin/anything`
- `audit/anything`
- `logs/anything`

Blob paths are virtual (Azure Storage is flat), so `signin/entra/20251123.json` matches the `signin` prefix. You can be more granular: `"prefixMatch": ["signin/entra"]` would only target that subtree.

Azure allows up to 100 rules per Storage Account. By consolidating multiple containers into a single rule with an array of prefixes, you stay well under quota and keep the policy maintainable.

## Handling Snapshots

Blobs can have snapshots (point-in-time immutable copies). If you delete a base blob but leave snapshots orphaned, they continue consuming storage and cost. Lifecycle policies have a dedicated `snapshot` action:

```json
"actions": {
  "baseBlob": {
    "delete": {
      "daysAfterModificationGreaterThan": 7
    }
  },
  "snapshot": {
    "delete": {
      "daysAfterCreationGreaterThan": 7
    }
  }
}
```

Note the difference:

- **Base blobs** use `daysAfterModificationGreaterThan` (when the blob was last written)
- **Snapshots** use `daysAfterCreationGreaterThan` (when the snapshot was created, which is immutable)

This ensures snapshots older than 7 days are purged alongside their parent, keeping storage tidy.

## Tiering Before Deletion (Cost Optimization)

If your access patterns allow, you can tier blobs to cooler storage (Cool or Archive) before deleting them entirely. This reduces storage costs while retaining data for a grace period.

```json
"actions": {
  "baseBlob": {
    "tierToCool": {
      "daysAfterModificationGreaterThan": 7
    },
    "tierToArchive": {
      "daysAfterModificationGreaterThan": 30
    },
    "delete": {
      "daysAfterModificationGreaterThan": 90
    }
  }
}
```

Lifecycle:

1. **Day 7**: Blob moves to Cool tier (lower storage cost, higher access cost)
2. **Day 30**: Blob moves to Archive tier (lowest storage cost, high rehydration cost)
3. **Day 90**: Blob deleted permanently

This staged approach is common in compliance scenarios where you need to retain data for auditing but can tolerate slower access as it ages.

Reference: [Access tiers for blob data](https://learn.microsoft.com/azure/storage/blobs/access-tiers-overview)

## Blob Versioning and Lifecycle Policies

If versioning is enabled on your Storage Account, every overwrite creates a new version. Old versions can accumulate quickly. Lifecycle policies support version-specific actions:

```json
"actions": {
  "version": {
    "delete": {
      "daysAfterCreationGreaterThan": 30
    }
  }
}
```

This deletes non-current versions older than 30 days, keeping only the latest version and recent history.

Reference: [Blob versioning](https://learn.microsoft.com/azure/storage/blobs/versioning-overview)

## Last Access Time Tracking

Azure Storage can optionally track when each blob was last read (requires enabling access time tracking on the account). Policies can then delete blobs that haven't been accessed recently, even if they're modified frequently:

```json
"actions": {
  "baseBlob": {
    "enableAutoTierToHotFromCool": {
      "daysAfterLastAccessTimeGreaterThan": 30
    },
    "delete": {
      "daysAfterLastAccessTimeGreaterThan": 90
    }
  }
}
```

This is powerful for log archives or cold data lakes where "staleness" means "nobody's reading this anymore" rather than "nobody's writing to this anymore."

Reference: [Optimize costs by automatically managing the data lifecycle](https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-policy-configure)

## Deploying with Bicep

Bicep lets you version, test, and deploy lifecycle policies as infrastructure-as-code. Here's a minimal module:

```bicep
// lifecyclePolicy.bicep
param storageAccountName string
param containerPrefixes array
param retentionDays int = 7

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: storageAccountName
}

resource managementPolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-01-01' = {
  name: 'default'
  parent: storageAccount
  properties: {
    policy: {
      rules: [
        {
          name: 'DeleteOldBlobs'
          enabled: true
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: ['blockBlob']
              prefixMatch: containerPrefixes
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: retentionDays
                }
              }
              snapshot: {
                delete: {
                  daysAfterCreationGreaterThan: retentionDays
                }
              }
            }
          }
        }
      ]
    }
  }
}
```

Reference: [Microsoft.Storage/storageAccounts/managementPolicies](https://learn.microsoft.com/azure/templates/microsoft.storage/storageaccounts/managementpolicies)

Deploy with environment-specific parameters:

```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "rg-prod" `
  -TemplateFile ./infra/main.bicep `
  -TemplateParameterFile ./infra/parameters.prod.json
```

Parameter files let you vary container lists and retention periods across dev/test/prod without duplicating Bicep code.

Reference: [New-AzResourceGroupDeployment](https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest)

## Multi-Environment Strategy

Structure parameter files like this:

**parameters.dev.json** (aggressive cleanup for fast iteration):

```json
{
  "storageAccountName": { "value": "stdevblobcleanup001" },
  "containerPrefixes": { "value": ["testA", "testB"] },
  "retentionDays": { "value": 2 }
}
```

**parameters.prod.json** (conservative retention):

```json
{
  "storageAccountName": { "value": "stprodblobcleanup001" },
  "containerPrefixes": { "value": ["signin", "audit", "logs"] },
  "retentionDays": { "value": 90 }
}
```

Same Bicep template, different behavior per environment. Version control tracks changes; CI/CD pipelines enforce review gates before production deployments.

## When to Use Lifecycle Policies vs Custom Code

**Use lifecycle policies when:**

- Retention logic is purely time-based (days since modification/creation/access)
- You want zero operational overhead (no Functions, no logs to monitor)
- Filters are simple (blob type, container prefix, blob name prefix)
- Tiering and deletion are sufficient actions

**Use custom code (e.g., Azure Functions) when:**

- You need filename parsing or complex business logic (e.g., "delete if filename matches pattern X")
- Per-run reporting is required (deletion counts per container logged to App Insights)
- You need conditional behavior (demo mode vs real mode, dry-run logic)
- Integration with external systems (send notifications, update databases, emit custom metrics)

Lifecycle policies are elegant for straightforward retention; custom code is the escape hatch for everything else.

## Testing Your Policy

Before enabling a policy in production, seed test data with the provided `Seed-StorageContainers.ps1` script:

```powershell
./scripts/Seed-StorageContainers.ps1 `
  -StorageAccountName "stdevblobcleanup001" `
  -ResourceGroup "rg-dev" `
  -PastDays 10 `
  -FutureDays 2
```

This creates blobs with filenames encoding timestamps (e.g., `signin/entra/20251113000000.json`). Deploy your policy with a short retention window (`retentionDays: 2`) and check after the next daily evaluation cycle (typically within 24 hours) whether old blobs were deleted.

**Important caveat**: Lifecycle policies evaluate `LastModified` or creation time, not filename content. The seeding script sets blob metadata timestamps to match filename patterns for accurate testing.

## Monitoring and Observability

Lifecycle policy executions don't emit logs to Application Insights or Azure Functions invocation history. To track deletions:

1. **Storage Analytics Logs**: Enable logging on the Storage Account; deletion operations appear in `$logs` container
2. **Azure Monitor Metrics**: Track container-level metrics (blob count, capacity)
3. **Log Analytics Integration**: Route diagnostic logs to a Log Analytics workspace and query `StorageBlobLogs`

Reference: [Monitor Azure Blob Storage](https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage)

Example Kusto query for deletion tracking:

```kusto
StorageBlobLogs
| where OperationName == "DeleteBlob"
| where TimeGenerated > ago(7d)
| summarize DeletionCount = count() by ContainerName = split(Uri, "/")[3]
| order by DeletionCount desc
```

## Extending the Bicep Module

The lifecycle policy module can grow with your needs. Add parameters for:

- **Tiering actions**: Expose `tierToCool`, `tierToArchive` with separate thresholds
- **Version cleanup**: Add `version.delete` action if versioning enabled
- **Multiple rules**: Loop over an array of rule definitions for complex scenarios
- **Conditional deployment**: Use Bicep conditionals to deploy policies only if certain features are enabled (e.g., versioning, soft delete)

Bicep's modular design keeps the core template simple while allowing opt-in complexity.

Reference: [Bicep Best Practices](https://learn.microsoft.com/azure/azure-resource-manager/bicep/best-practices)

## Wrapping Up

Azure Storage Lifecycle Management Policies are the right tool when retention is time-based and you value operational simplicity over granular control. Deploy them with Bicep, test with realistic data, and let the service handle the rest. Your infrastructure stays declarative, your storage costs stay predictable, and you avoid the operational overhead of maintaining yet another background job.

For scenarios demanding filename parsing, per-run reporting, or conditional logic, custom code remains the escape hatch—but for most cleanup workloads, the built-in lifecycle engine is enough.
