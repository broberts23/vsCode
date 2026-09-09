targetScope = 'resourceGroup'

extension microsoftGraphV1

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

@description('Execution mode for the vending machine')
@allowed([
  'DryRun'
  'Live'
])
param executionMode string = 'DryRun'

@description('Relative path to the offer catalog file')
param offerCatalogPath string = 'catalog/app-offerings.json'

@description('Whether to assign Microsoft Graph application permissions to the worker managed identity')
param assignWorkerGraphPermissions bool = true

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
var workerIdentityName = 'id-${baseName}-worker-${deploymentEnvironment}-${uniqueSuffix}'
var apiAppRegistrationName = 'app-${baseName}-api-${deploymentEnvironment}-${uniqueSuffix}'
var apiAppUniqueName = toLower(replace('${baseName}-api-${deploymentEnvironment}-${uniqueSuffix}', ' ', '-'))
var submitterRoleId = guid(resourceGroup().id, baseName, 'AppVending.Submitter')
var adminRoleId = guid(resourceGroup().id, baseName, 'AppVending.Admin')
var apiAudience = 'api://${apiAppUniqueName}'

// Well-known Microsoft Graph application permission role IDs
// https://learn.microsoft.com/graph/permissions-reference
var graphApplicationReadWriteOwnedByRoleId = '18a4783c-866b-4cc7-a460-3d5e5662c884'
var graphPolicyReadAllRoleId = '246ddfdf-e6c3-4d72-b48f-42b9744a17ce'
var graphPolicyReadWriteConditionalAccessRoleId = '01c0a623-fc9b-48e9-b794-0756f8e8f067'

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

resource workerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: workerIdentityName
  location: location
  tags: tags
}

resource apiAppRegistration 'Microsoft.Graph/applications@v1.0' = {
  displayName: apiAppRegistrationName
  uniqueName: apiAppUniqueName
  signInAudience: 'AzureADMyOrg'
  identifierUris: [
    apiAudience
  ]
  api: {
    requestedAccessTokenVersion: 2
  }
  appRoles: [
    {
      allowedMemberTypes: [
        'User'
        'Application'
      ]
      description: 'Submit application registration vending requests.'
      displayName: 'App Vending Submitter'
      id: submitterRoleId
      isEnabled: true
      value: 'AppVending.Submitter'
    }
    {
      allowedMemberTypes: [
        'User'
        'Application'
      ]
      description: 'Administer the application registration vending machine.'
      displayName: 'App Vending Admin'
      id: adminRoleId
      isEnabled: true
      value: 'AppVending.Admin'
    }
  ]
}

resource apiServicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' = {
  appId: apiAppRegistration.appId
  displayName: apiAppRegistration.displayName
}

resource microsoftGraphServicePrincipal 'Microsoft.Graph/servicePrincipals@v1.0' existing = {
  appId: '00000003-0000-0000-c000-000000000000'
}

resource workerGraphAppReadWriteOwnedBy 'Microsoft.Graph/appRoleAssignedTo@v1.0' = if (assignWorkerGraphPermissions) {
  appRoleId: graphApplicationReadWriteOwnedByRoleId
  principalId: workerIdentity.properties.principalId
  resourceId: microsoftGraphServicePrincipal.id
}

resource workerGraphPolicyReadAll 'Microsoft.Graph/appRoleAssignedTo@v1.0' = if (assignWorkerGraphPermissions) {
  appRoleId: graphPolicyReadAllRoleId
  principalId: workerIdentity.properties.principalId
  resourceId: microsoftGraphServicePrincipal.id
}

resource workerGraphPolicyReadWriteConditionalAccess 'Microsoft.Graph/appRoleAssignedTo@v1.0' = if (assignWorkerGraphPermissions) {
  appRoleId: graphPolicyReadWriteConditionalAccessRoleId
  principalId: workerIdentity.properties.principalId
  resourceId: microsoftGraphServicePrincipal.id
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${workerIdentity.id}': {}
    }
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
        {
          name: 'AZURE_CLIENT_ID'
          value: workerIdentity.properties.clientId
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
        {
          name: 'GRAPH_TENANT_ID'
          value: tenantId
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
          clientId: apiAppRegistration.appId
          openIdIssuer: '${az.environment().authentication.loginEndpoint}${tenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [
            apiAudience
            apiAppRegistration.appId
          ]
        }
      }
    }
  }
}

output storageAccountName string = storageAccount.name
output functionAppName string = functionApp.name
output workerIdentityName string = workerIdentity.name
output workerIdentityClientId string = workerIdentity.properties.clientId
output workerIdentityPrincipalId string = workerIdentity.properties.principalId
output apiAppName string = apiApp.name
output apiAppHostname string = 'https://${apiApp.properties.defaultHostName}'
output applicationInsightsName string = applicationInsights.name
output apiAppRegistrationClientId string = apiAppRegistration.appId
output apiAppRegistrationObjectId string = apiAppRegistration.id
output apiServicePrincipalObjectId string = apiServicePrincipal.id
output apiAudience string = apiAudience
output submitterRoleId string = submitterRoleId
output adminRoleId string = adminRoleId
