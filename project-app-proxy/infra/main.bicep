@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Short alphanumeric prefix used in resource names (3-10 chars).')
@minLength(3)
@maxLength(10)
param namePrefix string = 'proxylab'

@description('External App Proxy base URL for the on-prem API.')
param onPremApiBaseUrl string

@description('Entra scope the Function MI uses for outbound calls (app role / .default).')
param onPremApiScope string

@description('Application (client) ID of the Entra app registration used by Easy Auth.')
param easyAuthClientId string

@description('Tenant ID for the Easy Auth OpenID issuer.')
param tenantId string = tenant().tenantId

@description('Flex Consumption max instances.')
@minValue(1)
@maxValue(10)
param maximumInstanceCount int = 1

@description('Flex Consumption instance memory (MB).')
@allowed([512, 2048, 4096])
param instanceMemoryMB int = 512

var uniqueSuffix = take(uniqueString(resourceGroup().id, namePrefix, location), 8)
// Storage: 3-24 lowercase alphanumeric. Prefix (>=3) + 'st' + 8-char suffix keeps length >= 13.
var storageAccountName = take('${replace(toLower(namePrefix), '-', '')}st${uniqueSuffix}', 24)
var functionAppName = take('${toLower(namePrefix)}-fn-${uniqueSuffix}', 60)
var planName = take('${toLower(namePrefix)}-plan-${uniqueSuffix}', 40)
var deploymentContainerName = take('app-package-${replace(functionAppName, '-', '')}', 63)

var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageQueueDataContributorRoleId = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var storageTableDataContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
var openIdIssuer = '${environment().authentication.loginEndpoint}${tenantId}/v2.0'

resource storageAccount 'Microsoft.Storage/storageAccounts@2026-06-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2026-06-01' = {
  parent: storageAccount
  name: 'default'
}

resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2026-06-01' = {
  parent: blobService
  name: deploymentContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource flexPlan 'Microsoft.Web/serverfarms@2025-03-01' = {
  name: planName
  location: location
  kind: 'functionapp'
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: flexPlan.id
    httpsOnly: true
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccount.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maximumInstanceCount
        instanceMemoryMB: instanceMemoryMB
      }
      runtime: {
        name: 'python'
        version: '3.14'
      }
    }
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
    }
  }
  dependsOn: [
    deploymentContainer
  ]

  resource appSettings 'config' = {
    name: 'appsettings'
    properties: {
      AzureWebJobsStorage__accountName: storageAccount.name
      AzureWebJobsStorage__credential: 'managedidentity'
      FUNCTIONS_EXTENSION_VERSION: '~4'
      ON_PREM_API_BASE_URL: onPremApiBaseUrl
      ON_PREM_API_SCOPE: onPremApiScope
    }
  }

  resource authSettings 'config' = {
    name: 'authsettingsV2'
    properties: {
      platform: {
        enabled: true
      }
      globalValidation: {
        requireAuthentication: true
        unauthenticatedClientAction: 'Return401'
      }
      identityProviders: {
        azureActiveDirectory: {
          enabled: true
          registration: {
            clientId: easyAuthClientId
            openIdIssuer: openIdIssuer
          }
          validation: {
            allowedAudiences: [
              easyAuthClientId
              'api://${easyAuthClientId}'
            ]
          }
        }
      }
      login: {
        tokenStore: {
          enabled: true
        }
      }
    }
  }
}

resource storageBlobDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, storageBlobDataOwnerRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageQueueDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, storageQueueDataContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageQueueDataContributorRoleId
    )
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, storageTableDataContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      storageTableDataContributorRoleId
    )
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output functionAppName string = functionApp.name
output functionAppHostname string = functionApp.properties.defaultHostName
output functionAppPrincipalId string = functionApp.identity.principalId
output storageAccountName string = storageAccount.name
output deploymentContainerName string = deploymentContainerName
output easyAuthClientId string = easyAuthClientId
output onPremApiScope string = onPremApiScope
