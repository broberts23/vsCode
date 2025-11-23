// lifecyclePolicy.bicep
// Module to configure Azure Blob Storage Lifecycle Management Policy
// Reference: https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-overview

@description('Name of the existing Storage Account')
param storageAccountName string

@description('Array of container name prefixes to apply lifecycle rules to')
param containerPrefixes array

@description('Number of days after modification before deleting base blobs')
param daysAfterModificationGreaterThan int = 7

@description('Number of days after creation before deleting snapshots')
param daysAfterCreationGreaterThan int = 7

@description('Enable or disable the lifecycle policy rule')
param enabled bool = true

// Reference the existing storage account
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' existing = {
  name: storageAccountName
}

// Define the management policy
// Reference: https://learn.microsoft.com/azure/templates/microsoft.storage/storageaccounts/managementpolicies
resource managementPolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2025-06-01' = {
  name: 'default'
  parent: storageAccount
  properties: {
    policy: {
      rules: [
        {
          name: 'DeleteOldBlobs'
          enabled: enabled
          type: 'Lifecycle'
          definition: {
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: containerPrefixes
            }
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: daysAfterModificationGreaterThan
                }
              }
              snapshot: {
                delete: {
                  daysAfterCreationGreaterThan: daysAfterCreationGreaterThan
                }
              }
            }
          }
        }
      ]
    }
  }
}

output policyName string = managementPolicy.name
output ruleName string = managementPolicy.properties.policy.rules[0].name
