targetScope = 'resourceGroup'

@description('Environment name')
@allowed([
  'dev'
  'test'
  'prod'
])
param deploymentEnvironment string = 'dev'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Base name for the deployment')
param baseName string = 'agentvend'

@description('Microsoft Entra tenant ID used by Easy Auth')
param tenantId string

@description('Client application ID accepted by Easy Auth')
param easyAuthClientId string

@description('Required application role expected by the Function App logic')
param requiredAdminRole string = 'Agent.Vending.Admin'

@description('Graph tenant hint used by the scaffold')
param graphTenantId string = tenantId

@description('Execution mode for the vending machine')
@allowed([
  'DryRun'
  'Live'
])
param executionMode string = 'DryRun'

@description('Relative path to the offer catalog file inside the Function App package')
param offerCatalogPath string = 'config/agent-offerings.sample.json'

@description('Default sponsor object IDs as comma-separated values')
param defaultAgentSponsorObjectIds string = ''

@description('Default owner object IDs as comma-separated values')
param defaultAgentOwnerObjectIds string = ''

@description('Tags to apply to resources')
param tags object = {
  Environment: deploymentEnvironment
  Application: 'AgentVendingMachine'
  ManagedBy: 'Bicep'
}

var uniqueSuffix = take(uniqueString(resourceGroup().id, baseName, deploymentEnvironment), 6)
var functionAppName = '${baseName}-func-${deploymentEnvironment}-${uniqueSuffix}'
var appServicePlanName = '${baseName}-asp-${deploymentEnvironment}-${uniqueSuffix}'
var storageAccountName = toLower(replace('${baseName}st${deploymentEnvironment}${uniqueSuffix}', '-', ''))
var appInsightsName = '${baseName}-appi-${deploymentEnvironment}-${uniqueSuffix}'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
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
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
  }
}

resource applicationInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'PowerShell|7.4'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsights.properties.ConnectionString
        }
        {
          name: 'AGENT_VENDING_EXECUTION_MODE'
          value: executionMode
        }
        {
          name: 'REQUIRED_ADMIN_ROLE'
          value: requiredAdminRole
        }
        {
          name: 'GRAPH_TENANT_ID'
          value: graphTenantId
        }
        {
          name: 'OFFER_CATALOG_PATH'
          value: offerCatalogPath
        }
        {
          name: 'DEFAULT_AGENT_SPONSOR_OBJECT_IDS'
          value: defaultAgentSponsorObjectIds
        }
        {
          name: 'DEFAULT_AGENT_OWNER_OBJECT_IDS'
          value: defaultAgentOwnerObjectIds
        }
      ]
    }
  }
}

resource authSettings 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
      runtimeVersion: '~1'
    }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
      redirectToProvider: 'azureactivedirectory'
    }
    login: {
      tokenStore: {
        enabled: true
      }
      preserveUrlFragmentsForLogins: true
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: easyAuthClientId
          openIdIssuer: '${az.environment().authentication.loginEndpoint}${tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [
            'api://${easyAuthClientId}'
            easyAuthClientId
          ]
        }
      }
    }
  }
}

output functionAppName string = functionApp.name
output functionAppHostname string = 'https://${functionApp.properties.defaultHostName}'
output functionAppPrincipalId string = functionApp.identity.principalId
output applicationInsightsName string = applicationInsights.name
output storageAccountName string = storageAccount.name