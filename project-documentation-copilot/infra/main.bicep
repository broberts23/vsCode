@description('Deployment environment name (dev, staging, prod)')
param deploymentEnvironment string = 'dev'

@description('Base name for resource naming')
param baseName string = 'doccopilot'

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('SKU for Azure AI Search (basic, standard, etc.)')
param searchSku string = 'basic'

var cognitiveServicesName = '${baseName}-cog-${deploymentEnvironment}'
var searchServiceName = '${baseName}-search-${deploymentEnvironment}'
var logAnalyticsName = '${baseName}-la-${deploymentEnvironment}'
var appInsightsName = '${baseName}-ai-${deploymentEnvironment}'

resource cognitiveServices 'Microsoft.CognitiveServices/accounts@2026-03-01' = {
  name: cognitiveServicesName
  location: location
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

resource searchService 'Microsoft.Search/searchServices@2025-05-01' = {
  name: searchServiceName
  location: location
  sku: {
    name: searchSku
  }
  properties: {
    hostingMode: 'Default'
    publicNetworkAccess: 'enabled'
  }
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: logAnalyticsName
  location: location
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
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

output cognitiveServicesEndpoint string = cognitiveServices.properties.endpoint
output searchServiceEndpoint string = 'https://${searchServiceName}.search.windows.net'
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey
output location string = location
