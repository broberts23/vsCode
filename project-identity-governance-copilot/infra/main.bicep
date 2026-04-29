targetScope = 'resourceGroup'

// Bicep is Azure's declarative IaC language.
// If you know PowerShell deployment cmdlets, think of this file as the strongly typed template they submit.

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
param baseName string = 'idgovcopilot'

@description('Tags applied to all resources.')
param tags object = {
  Environment: deploymentEnvironment
  Application: 'IdentityGovernanceCopilot'
  ManagedBy: 'Bicep'
}

// These derived names use `uniqueString()` so repeated deployments stay deterministic inside one resource group.
@description('Azure AI Search service name.')
param searchServiceName string = toLower(substring('${baseName}${uniqueString(resourceGroup().id, deploymentEnvironment)}srch', 0, 24))

@description('Azure AI Search SKU.')
@allowed([
  'basic'
  'standard'
])
param searchSku string = 'basic'

@description('Storage account name used for artifacts or future staged content.')
param storageAccountName string = toLower(substring('${baseName}${uniqueString(resourceGroup().id, deploymentEnvironment)}st', 0, 24))

@description('Azure OpenAI account name.')
param openAiAccountName string = toLower(substring('${baseName}${uniqueString(resourceGroup().id, deploymentEnvironment)}aoai', 0, 24))

@description('Azure OpenAI deployment name referenced by the app.')
param openAiChatDeploymentName string = 'gpt-4o-mini'

@description('User-assigned managed identity name for app-side access.')
param userAssignedIdentityName string = '${baseName}-mi'

// `resource` blocks are the Bicep equivalent of declaratively describing desired Azure resources.
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
    disableLocalAuth: false
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2025-08-01' = {
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

resource openAi 'Microsoft.CognitiveServices/accounts@2025-12-01' = {
  name: openAiAccountName
  location: location
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  tags: tags
  properties: {
    publicNetworkAccess: 'Enabled'
    customSubDomainName: openAiAccountName
  }
}

resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: userAssignedIdentityName
  location: location
  tags: tags
}

// `output` values are returned after deployment so scripts can capture important endpoints and names.
output searchEndpoint string = 'https://${search.name}.search.windows.net'
output searchServiceName string = search.name
output openAiEndpoint string = openAi.properties.endpoint
output openAiChatDeploymentName string = openAiChatDeploymentName
output storageAccountName string = storage.name
output managedIdentityClientId string = managedIdentity.properties.clientId
