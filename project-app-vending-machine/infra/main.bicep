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
param baseName string = 'appvend'

@description('Microsoft Entra tenant ID used by Easy Auth')
param tenantId string

@description('Client application ID accepted by Easy Auth on the API Web App')
param easyAuthClientId string

@description('Execution mode for the vending machine')
@allowed([
  'DryRun'
  'Live'
])
param executionMode string = 'DryRun'

@description('Relative path to the offer catalog file')
param offerCatalogPath string = 'catalog/app-offerings.json'

@description('Tags to apply to resources')
param tags object = {
  Environment: deploymentEnvironment
  Application: 'AppVendingMachine'
  ManagedBy: 'Bicep'
}

var uniqueSuffix = take(uniqueString(resourceGroup().id, baseName, deploymentEnvironment), 6)
var storageAccountName = toLower(replace('${baseName}st${deploymentEnvironment}${uniqueSuffix}', '-', ''))
var functionAppName = '${baseName}-worker-${deploymentEnvironment}-${uniqueSuffix}'
var functionPlanName = '${baseName}-funcplan-${deploymentEnvironment}-${uniqueSuffix}'
var apiPlanName = '${baseName}-apiplan-${deploymentEnvironment}-${uniqueSuffix}'
var apiAppName = '${baseName}-api-${deploymentEnvironment}-${uniqueSuffix}'
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

resource functionPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: functionPlanName
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

resource apiPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: apiPlanName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: 'B1'
    tier: 'Basic'
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
    serverFarmId: functionPlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
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
          name: 'APP_VENDING_EXECUTION_MODE'
          value: executionMode
        }
        {
          name: 'GRAPH_TENANT_ID'
          value: tenantId
        }
        {
          name: 'OFFER_CATALOG_PATH'
          value: offerCatalogPath
        }
        {
          name: 'REQUIRED_SUBMITTER_ROLES'
          value: 'AppVending.Submitter,AppVending.Admin'
        }
      ]
    }
  }
}

resource apiApp 'Microsoft.Web/sites@2023-12-01' = {
  name: apiAppName
  location: location
  tags: tags
  kind: 'app,linux'
  properties: {
    serverFarmId: apiPlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
        {
          name: 'APP_VENDING_EXECUTION_MODE'
          value: executionMode
        }
        {
          name: 'OFFER_CATALOG_PATH'
          value: offerCatalogPath
        }
        {
          name: 'REQUIRED_SUBMITTER_ROLES'
          value: 'AppVending.Submitter,AppVending.Admin'
        }
      ]
    }
  }
}

resource apiAuthSettings 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: apiApp
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

output storageAccountName string = storageAccount.name
output functionAppName string = functionApp.name
output functionAppPrincipalId string = functionApp.identity.principalId
output apiAppName string = apiApp.name
output apiAppHostname string = 'https://${apiApp.properties.defaultHostName}'
output applicationInsightsName string = applicationInsights.name
