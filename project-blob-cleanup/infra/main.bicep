// main.bicep
// Main entry point for deploying Azure Blob Storage Lifecycle Management Policy
// Reference: https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview

targetScope = 'resourceGroup'

@description('Name of the existing Storage Account to configure')
param storageAccountName string

@description('Array of container name prefixes for lifecycle policy')
param containerPrefixes array

@description('Days after modification before deleting blobs')
@minValue(1)
@maxValue(36500)
param retentionDays int = 7

@description('Enable the lifecycle policy rule')
param enabled bool = true

// Deploy the lifecycle policy module
module lifecyclePolicy 'modules/lifecyclePolicy.bicep' = {
  name: 'lifecyclePolicyDeployment'
  params: {
    storageAccountName: storageAccountName
    containerPrefixes: containerPrefixes
    daysAfterModificationGreaterThan: retentionDays
    daysAfterCreationGreaterThan: retentionDays
    enabled: enabled
  }
}

output storageAccountName string = storageAccountName
output containerPrefixes array = containerPrefixes
output retentionDays int = retentionDays
output policyName string = lifecyclePolicy.outputs.policyName
