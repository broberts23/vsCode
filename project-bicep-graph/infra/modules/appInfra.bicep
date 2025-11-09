// Placeholder infrastructure (Key Vault, Storage) and RBAC assignments.
// Fill in real resource properties as needed. RBAC uses role assignments referencing the service principal objectId.
// Key Vault RBAC model recommended (enableRbacAuthorization=true).
// Built-in roles reference: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles

param prNumber int
param location string
param servicePrincipalObjectId string
@description('Application audience/identifier URI')
param appAudience string
@description('ISO8601 created timestamp for tagging')
param createdAt string = 'n/a'
@description('Optional: service principal objectId of the GitHub runner (OIDC workload identity) to grant Key Vault Secrets User for smoke tests.')
param runnerPrincipalObjectId string = ''

@description('Optional storage account name override.')
param storageName string = toLower(replace('st${uniqueString(resourceGroup().id, string(prNumber))}', '-', ''))

@description('Client ID of the application (app ID).')
param clientId string

var kvName = toLower('kv-${uniqueString(resourceGroup().id, string(prNumber))}')
var planName = toLower('plan-${uniqueString(resourceGroup().id, string(prNumber))}')
var webName = toLower('api-${uniqueString(resourceGroup().id, string(prNumber))}')
var tags = {
  Env: 'pr-${prNumber}'
  CreatedAt: createdAt
}

// Storage Account (placeholder properties simplified)
resource storage 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  tags: tags
}

// Key Vault (placeholder minimal)
resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: kvName
  location: location
  properties: {
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    sku: {
      name: 'standard'
      family: 'A'
    }
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
  tags: tags
}

// Role assignment placeholders — assign minimal roles (adjust roleDefinitionId GUIDs appropriately).
// Example GUIDs: Key Vault Secrets User (4633458b-17de-408a-b874-0445c86b69e6
@description('Role definition ID to assign on Key Vault scope')
param keyVaultRoleDefinitionId string = '4633458b-17de-408a-b874-0445c86b69e6'

resource kvRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, servicePrincipalObjectId, keyVaultRoleDefinitionId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultRoleDefinitionId)
    principalId: servicePrincipalObjectId
    principalType: 'ServicePrincipal'
  }
  scope: keyVault
}

// Optional: assign same Key Vault role to the GitHub runner service principal so smoke tests can access secrets without extra manual RBAC.
resource kvRunnerRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (runnerPrincipalObjectId != '') {
  name: guid(keyVault.id, runnerPrincipalObjectId, keyVaultRoleDefinitionId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultRoleDefinitionId)
    principalId: runnerPrincipalObjectId
    principalType: 'ServicePrincipal'
  }
  scope: keyVault
}

// App Service Plan (Free tier for demo)
resource apiPlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  name: planName
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  tags: tags
}

// Web App hosting the API (expects container or code deployment separately)
resource apiSite 'Microsoft.Web/sites@2024-11-01' = {
  name: webName
  location: location
  properties: {
    httpsOnly: true
    serverFarmId: apiPlan.id
    siteConfig: {
      appSettings: [
        {
          name: 'AzureAd__TenantId'
          value: subscription().tenantId
        }
        {
          name: 'AzureAd__Audience'
          value: appAudience
        }
        {
          name: 'AzureAd__ClientId'
          value: clientId
        }
      ]
    }
  }
  tags: tags
}

output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output storageAccountName string = storage.name
output storageAccountId string = storage.id
output webAppName string = apiSite.name
output webAppUrl string = 'https://${apiSite.name}.azurewebsites.net'
