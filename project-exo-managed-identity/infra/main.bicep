targetScope = 'resourceGroup'

// ====================================
// Parameters
// ====================================

@description('Environment name (dev, test, prod)')
@allowed(['dev', 'test', 'prod'])
param environment string = 'dev'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Base name for all resources')
param baseName string = 'exomi'

@description('Tags to apply to all resources')
param tags object = {
  Environment: environment
  Application: 'ExoManagedIdentity'
  ManagedBy: 'Bicep'
}

@description('Tenant *.onmicrosoft.com domain for Connect-ExchangeOnline -Organization')
param exchangeOrganization string

// ====================================
// Variables
// ====================================

var uniqueSuffix = uniqueString(resourceGroup().id, baseName)
var functionAppName = '${baseName}-func-${environment}-${uniqueSuffix}'
var appServicePlanName = '${baseName}-asp-${environment}-${uniqueSuffix}'
var storageAccountName = '${baseName}st${environment}${take(uniqueSuffix, 8)}'
var logAnalyticsName = '${baseName}-log-${environment}-${uniqueSuffix}'
var appInsightsName = '${baseName}-ai-${environment}-${uniqueSuffix}'

// ====================================
// Resources
// ====================================

// Log Analytics Workspace
// https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Application Insights
// https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Storage Account for Function App
// https://learn.microsoft.com/azure/storage/common/storage-account-overview
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// App Service Plan (Elastic Premium - Windows)
// PowerShell 7.6 is Windows-only on Azure Functions.
// https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell
resource appServicePlan 'Microsoft.Web/serverfarms@2025-03-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  sku: {
    name: 'EP1'
    tier: 'ElasticPremium'
  }
  kind: 'functionapp'
  properties: {
    reserved: false
  }
}

// Function App with system-assigned managed identity
// https://learn.microsoft.com/azure/azure-functions/functions-overview
resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    reserved: false
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      powerShellVersion: '7.6'
      use32BitWorkerProcess: false
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      functionAppScaleLimit: 200
      minimumElasticInstanceCount: 1
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME_VERSION'
          value: '7.6'
        }
        {
          name: 'FUNCTIONS_WORKER_PROCESS_COUNT'
          value: '1'
        }
        {
          name: 'PSWorkerInProcConcurrencyUpperBound'
          value: '2'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppName)
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'EXCHANGE_ORGANIZATION'
          value: exchangeOrganization
        }
      ]
    }
  }
}

// ====================================
// Outputs
// ====================================

output functionAppName string = functionApp.name
output functionAppHostname string = functionApp.properties.defaultHostName
output functionAppPrincipalId string = functionApp.identity.principalId
output functionAppId string = functionApp.id
output storageAccountName string = storageAccount.name
output appInsightsName string = appInsights.name
output logAnalyticsName string = logAnalyticsWorkspace.name
