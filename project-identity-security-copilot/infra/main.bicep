targetScope = 'resourceGroup'

@description('Deployment environment name.')
@allowed([
  'dev'
  'test'
  'prod'
])
param deploymentEnvironment string = 'dev'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Base name used for resource naming.')
param baseName string = 'idseccopilot'

@description('Azure AI Search SKU.')
@allowed([
  'basic'
  'standard'
])
param searchSku string = 'basic'

@description('Tags applied to all resources.')
param tags object = {
  Environment: deploymentEnvironment
  Application: 'IdentitySecurityCopilot'
  ManagedBy: 'Bicep'
}

var searchServiceName = toLower(substring('${baseName}${uniqueString(resourceGroup().id, deploymentEnvironment)}srch', 0, 24))
var storageAccountName = toLower(substring('${baseName}${uniqueString(resourceGroup().id, deploymentEnvironment)}st', 0, 24))
var appConfigName = toLower(substring('${baseName}${uniqueString(resourceGroup().id, deploymentEnvironment)}cfg', 0, 50))
var keyVaultName = toLower(substring('${baseName}-${uniqueString(resourceGroup().id, deploymentEnvironment)}-kv', 0, 24))
var logAnalyticsName = '${baseName}-${deploymentEnvironment}-law'
var appInsightsName = '${baseName}-${deploymentEnvironment}-appi'
var userAssignedIdentityName = '${baseName}-mi'

resource search 'Microsoft.Search/searchServices@2025-05-01' = {
  name: searchServiceName
  location: location
  sku: {
    name: searchSku
  }
  identity: {
    type: 'SystemAssigned'
  }
  tags: tags
  properties: {
    hostingMode: 'Default'
    publicNetworkAccess: 'enabled'
    semanticSearch: 'free'
    disableLocalAuth: true
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  tags: tags
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    publicNetworkAccess: 'Enabled'
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
  }
}

resource appConfig 'Microsoft.AppConfiguration/configurationStores@2024-05-01' = {
  name: appConfigName
  location: location
  sku: {
    name: 'standard'
  }
  tags: tags
  properties: {
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true
    enablePurgeProtection: false
    softDeleteRetentionInDays: 7
  }
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
  }
}

resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: userAssignedIdentityName
  location: location
  tags: tags
}

output searchEndpoint string = 'https://${search.name}.search.windows.net'
output searchServiceName string = search.name
output storageAccountName string = storage.name
output keyVaultUri string = keyVault.properties.vaultUri
output appConfigEndpoint string = appConfig.properties.endpoint
output logAnalyticsWorkspaceId string = workspace.properties.customerId
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output managedIdentityClientId string = managedIdentity.properties.clientId
