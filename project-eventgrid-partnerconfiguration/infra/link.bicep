targetScope = 'resourceGroup'

@description('Azure region for resources created by this template.')
param location string = resourceGroup().location

@description('Name of the user-assigned managed identity (in this resource group) used for Event Grid delivery/dead-lettering.')
param bootstrapUserAssignedIdentityName string

@description('Partner topic name created by the partner (Microsoft Graph) in this resource group.')
param partnerTopicName string

@description('Partner-provided source associated with this partner topic. Used to preserve required partner metadata when updating the topic.')
param partnerTopicSource string

@description('Event subscription name for the partner topic -> Function link.')
param partnerTopicEventSubscriptionName string = 'to-governance-function'

@description('ResourceId of the Azure Function to invoke.')
param functionResourceId string

@description('Name of the Storage Account used for Event Grid dead-lettering. Must be globally unique and 3-24 lowercase alphanumeric.')
param deadLetterStorageAccountName string = toLower('dls${uniqueString(resourceGroup().id)}')

@description('Blob container name used for Event Grid dead-letter delivery.')
param deadLetterContainerName string = 'eventgrid-deadletter'

var bootstrapIdentityResourceId = resourceId(
  'Microsoft.ManagedIdentity/userAssignedIdentities',
  bootstrapUserAssignedIdentityName
)
var bootstrapIdentityPrincipalId = reference(bootstrapIdentityResourceId, '2025-01-31-preview').principalId

// Update the partner topic to attach the UAMI, while keeping the partner-provided source.
resource partnerTopic 'Microsoft.EventGrid/partnerTopics@2025-02-15' = {
  name: partnerTopicName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${bootstrapIdentityResourceId}': {}
    }
  }
  properties: {
    source: partnerTopicSource
  }
}

resource deadLetterStorage 'Microsoft.Storage/storageAccounts@2025-06-01' = {
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

resource deadLetterBlobService 'Microsoft.Storage/storageAccounts/blobServices@2025-06-01' = {
  name: 'default'
  parent: deadLetterStorage
}

resource deadLetterContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2025-06-01' = {
  name: deadLetterContainerName
  parent: deadLetterBlobService
  properties: {
    publicAccess: 'None'
  }
}

// Built-in role: Storage Blob Data Contributor
var storageBlobDataContributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)

resource deadLetterStorageBlobDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(deadLetterStorage.id, bootstrapIdentityResourceId, storageBlobDataContributorRoleDefinitionId)
  scope: deadLetterStorage
  properties: {
    roleDefinitionId: storageBlobDataContributorRoleDefinitionId
    principalId: bootstrapIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource partnerTopicEventSubscription 'Microsoft.EventGrid/partnerTopics/eventSubscriptions@2025-02-15' = {
  name: partnerTopicEventSubscriptionName
  parent: partnerTopic
  dependsOn: [
    deadLetterContainer
    deadLetterStorageBlobDataContributor
  ]
  properties: {
    destination: {
      endpointType: 'AzureFunction'
      properties: {
        resourceId: functionResourceId
      }
    }
    eventDeliverySchema: 'CloudEventSchemaV1_0'
    deadLetterWithResourceIdentity: {
      deadLetterDestination: {
        endpointType: 'StorageBlob'
        properties: {
          resourceId: deadLetterStorage.id
          blobContainerName: deadLetterContainerName
        }
      }
      identity: {
        type: 'UserAssigned'
        userAssignedIdentity: bootstrapIdentityResourceId
      }
    }
  }
}

output partnerTopicEventSubscriptionId string = partnerTopicEventSubscription.id
