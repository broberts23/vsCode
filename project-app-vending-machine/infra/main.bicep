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

// Built-in Azure RBAC role definition IDs
var roleStorageBlobDataOwner = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var roleStorageQueueDataContributor = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var roleStorageTableDataContributor = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var roleMonitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'

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
    allowSharedKeyAccess: false
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
    DisableLocalAuth: true
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

// Resolve role IDs from the Graph SP appRoles collection (do not hardcode GUIDs).
var graphAppReadWriteOwnedByRoleId = filter(microsoftGraphServicePrincipal.appRoles, role => role.value == 'Application.ReadWrite.OwnedBy')[0].id
var graphAppReadAllRoleId = filter(microsoftGraphServicePrincipal.appRoles, role => role.value == 'Application.Read.All')[0].id
var graphPolicyReadAllRoleId = filter(microsoftGraphServicePrincipal.appRoles, role => role.value == 'Policy.Read.All')[0].id
var graphPolicyReadWriteConditionalAccessRoleId = filter(microsoftGraphServicePrincipal.appRoles, role => role.value == 'Policy.ReadWrite.ConditionalAccess')[0].id

resource workerGraphAppReadWriteOwnedBy 'Microsoft.Graph/appRoleAssignedTo@v1.0' = if (assignWorkerGraphPermissions) {
  appRoleId: graphAppReadWriteOwnedByRoleId
  principalId: workerIdentity.properties.principalId
  resourceId: microsoftGraphServicePrincipal.id
}

resource workerGraphAppReadAll 'Microsoft.Graph/appRoleAssignedTo@v1.0' = if (assignWorkerGraphPermissions) {
  appRoleId: graphAppReadAllRoleId
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
    type: 'SystemAssigned, UserAssigned'
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
          // API enqueue uses plain JSON; default Functions queue encoding is Base64.
          name: 'AzureFunctionsJobHost__extensions__queues__messageEncoding'
          value: 'none'
        }
        {
          // Identity-based host storage (system-assigned MI; omit __clientId).
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccount.name
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'STORAGE_ACCOUNT_NAME'
          value: storageAccount.name
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: applicationInsights.properties.ConnectionString
        }
        {
          name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING'
          value: 'Authorization=AAD'
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
          // Graph control plane uses the user-assigned identity only.
          name: 'WORKER_CLIENT_ID'
          value: workerIdentity.properties.clientId
        }
        {
          name: 'WORKER_PRINCIPAL_ID'
          value: workerIdentity.properties.principalId
        }
        {
          name: 'UTCM_OUTPUT_DIR'
          value: '/home/data/utcm'
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
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
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: apiPlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appCommandLine: 'python -m gunicorn -w 2 -k uvicorn.workers.UvicornWorker api.main:app --bind=0.0.0.0:8000'
      appSettings: [
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'false'
        }
        {
          name: 'ENABLE_ORYX_BUILD'
          value: 'false'
        }
        {
          name: 'WEBSITES_PORT'
          value: '8000'
        }
        {
          name: 'PYTHONPATH'
          value: '/home/site/wwwroot:/home/site/wwwroot/.python_packages/lib/site-packages'
        }
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccount.name
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'STORAGE_ACCOUNT_NAME'
          value: storageAccount.name
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
      excludedPaths: [
        '/health'
      ]
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

// Disable SCM/FTP basic publishing credentials (AAD deploy only).
resource functionAppScmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: functionApp
  name: 'scm'
  properties: {
    allow: false
  }
}

resource functionAppFtpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: functionApp
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource apiAppScmBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: apiApp
  name: 'scm'
  properties: {
    allow: false
  }
}

resource apiAppFtpBasicAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: apiApp
  name: 'ftp'
  properties: {
    allow: false
  }
}

// Function system MI → Storage (host + app data plane)
resource functionStorageBlobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, roleStorageBlobDataOwner)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageBlobDataOwner)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource functionStorageQueueContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, roleStorageQueueDataContributor)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageQueueDataContributor)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource functionStorageTableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, roleStorageTableDataContributor)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageTableDataContributor)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// API system MI → Storage (queue + table only)
resource apiStorageQueueContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, apiApp.id, roleStorageQueueDataContributor)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageQueueDataContributor)
    principalId: apiApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource apiStorageTableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, apiApp.id, roleStorageTableDataContributor)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleStorageTableDataContributor)
    principalId: apiApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Function system MI → App Insights AAD ingestion
resource functionAppInsightsMetricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(applicationInsights.id, functionApp.id, roleMonitoringMetricsPublisher)
  scope: applicationInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleMonitoringMetricsPublisher)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output storageAccountName string = storageAccount.name
output functionAppName string = functionApp.name
output functionAppPrincipalId string = functionApp.identity.principalId
output workerIdentityName string = workerIdentity.name
output workerIdentityClientId string = workerIdentity.properties.clientId
output workerIdentityPrincipalId string = workerIdentity.properties.principalId
output apiAppName string = apiApp.name
output apiAppPrincipalId string = apiApp.identity.principalId
output apiAppHostname string = 'https://${apiApp.properties.defaultHostName}'
output applicationInsightsName string = applicationInsights.name
output apiAppRegistrationClientId string = apiAppRegistration.appId
output apiAppRegistrationObjectId string = apiAppRegistration.id
output apiServicePrincipalObjectId string = apiServicePrincipal.id
output apiAudience string = apiAudience
output submitterRoleId string = submitterRoleId
output adminRoleId string = adminRoleId
