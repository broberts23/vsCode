targetScope = 'resourceGroup'

@description('Azure region for the partner configuration resource.')
param location string = resourceGroup().location

@description('Name of the partner configuration resource. Many deployments use `default`.')
param partnerConfigurationName string = 'default'

@description('The immutable ID of the partner registration to authorize. Leave empty to manage authorizations out-of-band.')
param authorizedPartnerRegistrationImmutableId string = ''

@description('Partner name to authorize in Event Grid Partner Configuration. Defaults to MicrosoftGraphAPI (Microsoft Graph API partner).')
param authorizedPartnerName string = 'MicrosoftGraphAPI'

@description('Expiration time (UTC) for the partner authorization entry. Defaults to 7 days from deployment time.')
param authorizedPartnerAuthorizationExpirationTimeInUtc string = dateTimeAdd(utcNow(), 'P7D')

@description('Name of the Log Analytics workspace used for Function App diagnostics.')
param logAnalyticsWorkspaceName string = 'law-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Retention (days) for the Log Analytics workspace.')
param logAnalyticsRetentionInDays int = 30

@description('Name of a user-assigned managed identity (in this resource group) used by the Function App (and used by deployment tooling for Graph bootstrap).')
param bootstrapUserAssignedIdentityName string = ''

@description('Partner topic name used by Microsoft Graph. When provided, the template can create/update the partner topic event subscription to the Function.')
param partnerTopicName string = ''

@description('Event subscription name for the partner topic -> Function link (only used when partnerTopicName is set).')
param partnerTopicEventSubscriptionName string = 'to-governance-function'

@description('ResourceId of the Azure Function to invoke. If empty, uses the function deployed by this template (only used when partnerTopicName is set).')
param functionResourceId string = ''

var bootstrapIdentityResourceId = !empty(bootstrapUserAssignedIdentityName)
  ? resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', bootstrapUserAssignedIdentityName)
  : ''

var bootstrapIdentityClientId = !empty(bootstrapUserAssignedIdentityName)
  ? reference(bootstrapIdentityResourceId, '2025-01-31-preview').clientId
  : ''

var bootstrapIdentityPrincipalId = !empty(bootstrapUserAssignedIdentityName)
  ? reference(bootstrapIdentityResourceId, '2025-01-31-preview').principalId
  : ''

@description('Name of the Windows Function App (Microsoft.Web/sites).')
param functionAppName string = 'func-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Name of the Consumption plan (Microsoft.Web/serverfarms).')
param appServicePlanName string = 'plan-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Name of the Storage Account used by the Function App. Must be globally unique and 3-24 lowercase alphanumeric.')
param storageAccountName string = toLower('st${uniqueString(resourceGroup().id)}')

@description('Name of the Storage Account used for Event Grid dead-lettering. Must be globally unique and 3-24 lowercase alphanumeric.')
param deadLetterStorageAccountName string = toLower('dls${uniqueString(resourceGroup().id)}')

@description('Blob container name used for Event Grid dead-letter delivery.')
param deadLetterContainerName string = 'eventgrid-deadletter'

@description('Name of the Azure Function within the Function App that Event Grid should invoke.')
param functionName string = 'GovernanceEventHandler'

@description('Name of the Azure Table Storage table used for idempotency/dedupe.')
param dedupeTableName string = 'DedupeKeys'

@description('Name of the Azure Storage Queue used as a cheap buffer for work items.')
param workQueueName string = 'governance-workitems'

@description('Name of the Azure Storage Queue used for Microsoft Graph subscription lifecycle maintenance work items.')
param lifecycleQueueName string = 'governance-lifecycle'

type PartnerAuthorizationEntry = {
  partnerRegistrationImmutableId: string
  partnerName: string
}

var shouldAuthorizePartner = !empty(authorizedPartnerRegistrationImmutableId) || !empty(authorizedPartnerName)

var authorizedPartnerEntry = union(
  !empty(authorizedPartnerRegistrationImmutableId)
    ? {
        partnerRegistrationImmutableId: authorizedPartnerRegistrationImmutableId
      }
    : {},
  !empty(authorizedPartnerName)
    ? {
        partnerName: authorizedPartnerName
      }
    : {},
  !empty(authorizedPartnerAuthorizationExpirationTimeInUtc)
    ? {
        authorizationExpirationTimeInUtc: authorizedPartnerAuthorizationExpirationTimeInUtc
      }
    : {}
)

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    retentionInDays: logAnalyticsRetentionInDays
    sku: {
      name: 'PerGB2018'
    }
  }
}

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

resource functionStorageQueueService 'Microsoft.Storage/storageAccounts/queueServices@2025-06-01' = {
  name: 'default'
  parent: functionStorage
}

resource functionStorageWorkQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2025-06-01' = {
  name: workQueueName
  parent: functionStorageQueueService
}

resource functionStorageLifecycleQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2025-06-01' = {
  name: lifecycleQueueName
  parent: functionStorageQueueService
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
    // The deployment orchestrator always provisions a UAMI and passes bootstrapUserAssignedIdentityName.
    // This Function App uses only the UAMI (no system-assigned identity).
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${bootstrapIdentityResourceId}': {}
    }
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
        {
          name: 'WORK_QUEUE_NAME'
          value: workQueueName
        }
        {
          name: 'LIFECYCLE_QUEUE_NAME'
          value: lifecycleQueueName
        }
        {
          name: 'MANAGED_IDENTITY_CLIENT_ID'
          value: bootstrapIdentityClientId
        }
        // Identity-based connection for Storage Queue triggers/bindings.
        // See: https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference#common-properties-for-identity-based-connections
        {
          name: 'WorkQueue__queueServiceUri'
          value: functionStorage.properties.primaryEndpoints.queue
        }
        {
          name: 'WorkQueue__credential'
          value: 'managedidentity'
        }
        {
          name: 'WorkQueue__clientId'
          value: bootstrapIdentityClientId
        }
      ]
    }
  }
}

resource functionAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-loganalytics'
  scope: functionApp
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
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
  name: guid(functionStorage.id, bootstrapIdentityResourceId, storageTableDataContributorRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
    principalId: bootstrapIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Data-plane RBAC for Queue access via the Function's managed identity.
// Built-in roles:
// - Storage Queue Data Message Processor (trigger)
// - Storage Queue Data Message Sender (output)
var storageQueueDataMessageProcessorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '8a0f0c08-91a1-4084-bc3d-661d67233fed'
)

var storageQueueDataMessageSenderRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'
)

resource functionAppStorageQueueDataMessageProcessor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, bootstrapIdentityResourceId, storageQueueDataMessageProcessorRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageQueueDataMessageProcessorRoleDefinitionId
    principalId: bootstrapIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource functionAppStorageQueueDataMessageSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, bootstrapIdentityResourceId, storageQueueDataMessageSenderRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageQueueDataMessageSenderRoleDefinitionId
    principalId: bootstrapIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Data-plane RBAC for Blob access via the Function's user-assigned managed identity.
// Built-in role: Storage Blob Data Contributor
var storageBlobDataContributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)

resource functionAppStorageBlobDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, bootstrapIdentityResourceId, storageBlobDataContributorRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageBlobDataContributorRoleDefinitionId
    principalId: bootstrapIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

var functionResourceIdOut = '${functionApp.id}/functions/${functionName}'
var effectiveFunctionResourceId = !empty(functionResourceId) ? functionResourceId : functionResourceIdOut

var shouldCreatePartnerTopicSubscription = !empty(partnerTopicName) && !empty(effectiveFunctionResourceId)

resource partnerConfiguration 'Microsoft.EventGrid/partnerConfigurations@2025-02-15' = {
  name: partnerConfigurationName
  location: 'global'
  properties: shouldAuthorizePartner
    ? {
        partnerAuthorization: {
          defaultMaximumExpirationTimeInDays: 7
          authorizedPartnersList: [
            {
              // Schema supports identifying the partner by immutable ID and/or name.
              // The authorizationExpirationTimeInUtc is recommended for clarity.
              ...authorizedPartnerEntry
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
  dependsOn: [
    deadLetterContainer
  ]
  properties: {
    destination: {
      endpointType: 'AzureFunction'
      properties: {
        resourceId: effectiveFunctionResourceId
      }
    }
    eventDeliverySchema: 'CloudEventSchemaV1_0'
    deadLetterDestination: {
      endpointType: 'StorageBlob'
      properties: {
        resourceId: deadLetterStorage.id
        blobContainerName: deadLetterContainerName
      }
    }
  }
}

resource deadLetterStorage 'Microsoft.Storage/storageAccounts@2025-06-01' = if (shouldCreatePartnerTopicSubscription) {
  name: deadLetterStorageAccountName
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

resource deadLetterBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' = if (shouldCreatePartnerTopicSubscription) {
  name: 'default'
  parent: deadLetterStorage
}

resource deadLetterContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = if (shouldCreatePartnerTopicSubscription) {
  name: deadLetterContainerName
  parent: deadLetterBlobService
  properties: {
    publicAccess: 'None'
  }
}

resource deadLetterStorageBlobDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldCreatePartnerTopicSubscription) {
  name: guid(deadLetterStorage.id, bootstrapIdentityResourceId, storageBlobDataContributorRoleDefinitionId)
  scope: deadLetterStorage
  properties: {
    roleDefinitionId: storageBlobDataContributorRoleDefinitionId
    principalId: bootstrapIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

output partnerConfigurationId string = partnerConfiguration.id
output functionAppId string = functionApp.id
output functionResourceIdOut string = functionResourceIdOut

output partnerTopicEventSubscriptionId string = shouldCreatePartnerTopicSubscription
  ? partnerTopicEventSubscription.id
  : ''

output bootstrapIdentityName string = bootstrapUserAssignedIdentityName
output bootstrapIdentityClientId string = bootstrapIdentityClientId
output bootstrapIdentityPrincipalId string = bootstrapIdentityPrincipalId
