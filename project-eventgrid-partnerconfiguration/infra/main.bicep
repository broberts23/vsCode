targetScope = 'resourceGroup'

@description('Azure region for the partner configuration resource.')
param location string = resourceGroup().location

@description('Name of the partner configuration resource. Many deployments use `default`.')
param partnerConfigurationName string = 'default'

@description('Optional: the immutable ID of the partner registration to authorize. Leave empty to manage authorizations out-of-band.')
param authorizedPartnerRegistrationImmutableId string = ''

@description('Optional: partner name to document the authorization entry. Leave empty if not authorizing in this template.')
param authorizedPartnerName string = ''

@description('Optional: name of an existing partner topic. If empty, no event subscription is created by this template.')
param partnerTopicName string = ''

@description('Optional: event subscription name (only used if `partnerTopicName` is set).')
param partnerTopicEventSubscriptionName string = 'to-governance-function'

@description('Optional: resourceId of the Azure Function to invoke (only used if `partnerTopicName` is set). Example: /subscriptions/.../resourceGroups/.../providers/Microsoft.Web/sites/<app>/functions/<functionName>')
param functionResourceId string = ''

@description('Name of the Windows Function App (Microsoft.Web/sites).')
param functionAppName string = 'func-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Name of the Consumption plan (Microsoft.Web/serverfarms).')
param appServicePlanName string = 'plan-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Name of the Storage Account used by the Function App. Must be globally unique and 3-24 lowercase alphanumeric.')
param storageAccountName string = toLower('st${uniqueString(resourceGroup().id)}')

@description('Name of the Azure Function within the Function App that Event Grid should invoke.')
param functionName string = 'GovernanceEventHandler'

@description('Name of the Azure Table Storage table used for idempotency/dedupe.')
param dedupeTableName string = 'DedupeKeys'

type PartnerAuthorizationEntry = {
  partnerRegistrationImmutableId: string
  partnerName: string
}

var shouldAuthorizePartner = !empty(authorizedPartnerRegistrationImmutableId)

resource functionStorage 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource functionStorageTableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' = {
  name: 'default'
  parent: functionStorage
}

resource functionStorageDedupeTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  name: dedupeTableName
  parent: functionStorageTableService
}

resource functionPlan 'Microsoft.Web/serverfarms@2025-03-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {}
}

resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    httpsOnly: true
    serverFarmId: functionPlan.id
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};AccountKey=${functionStorage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};AccountKey=${functionStorage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower('${functionAppName}-content')
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'DEDUPE_ENABLED'
          value: 'true'
        }
        {
          name: 'DEDUPE_TABLE_NAME'
          value: dedupeTableName
        }
        {
          name: 'DEDUPE_STORAGE_ACCOUNT_NAME'
          value: functionStorage.name
        }
        {
          name: 'DEDUPE_ENDPOINT_SUFFIX'
          value: environment().suffixes.storage
        }
      ]
    }
  }
}

// Data-plane RBAC for Table Storage access via the Function's managed identity.
// Built-in role: Storage Table Data Contributor
// See: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
var storageTableDataContributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
)

resource functionAppStorageTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, functionApp.id, storageTableDataContributorRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

var deployedFunctionResourceId = '${functionApp.id}/functions/${functionName}'
var effectiveFunctionResourceId = !empty(functionResourceId) ? functionResourceId : deployedFunctionResourceId

var shouldCreatePartnerTopicSubscription = !empty(partnerTopicName) && !empty(effectiveFunctionResourceId)

resource partnerConfiguration 'Microsoft.EventGrid/partnerConfigurations@2025-02-15' = {
  name: partnerConfigurationName
  location: location
  properties: shouldAuthorizePartner
    ? {
        partnerAuthorization: {
          defaultMaximumExpirationTimeInDays: 7
          authorizedPartnersList: [
            {
              partnerRegistrationImmutableId: authorizedPartnerRegistrationImmutableId
              partnerName: authorizedPartnerName
            }
          ]
        }
      }
    : {}
}

resource partnerTopic 'Microsoft.EventGrid/partnerTopics@2025-02-15' existing = if (shouldCreatePartnerTopicSubscription) {
  name: partnerTopicName
}

resource partnerTopicEventSubscription 'Microsoft.EventGrid/partnerTopics/eventSubscriptions@2025-02-15' = if (shouldCreatePartnerTopicSubscription) {
  name: partnerTopicEventSubscriptionName
  parent: partnerTopic
  properties: {
    destination: {
      endpointType: 'AzureFunction'
      properties: {
        resourceId: effectiveFunctionResourceId
      }
    }
    eventDeliverySchema: 'EventGridSchema'
  }
}

output partnerConfigurationId string = partnerConfiguration.id
output functionAppId string = functionApp.id
output functionResourceIdOut string = effectiveFunctionResourceId
output partnerTopicEventSubscriptionId string = shouldCreatePartnerTopicSubscription
  ? partnerTopicEventSubscription.id
  : ''
