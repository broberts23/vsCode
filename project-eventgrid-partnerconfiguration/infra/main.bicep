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

type PartnerAuthorizationEntry = {
  partnerRegistrationImmutableId: string
  partnerName: string
}

var shouldAuthorizePartner = !empty(authorizedPartnerRegistrationImmutableId)
var shouldCreatePartnerTopicSubscription = !empty(partnerTopicName) && !empty(functionResourceId)

resource partnerConfiguration 'Microsoft.EventGrid/partnerConfigurations@2025-02-15' = {
  name: partnerConfigurationName
  location: location
  properties: shouldAuthorizePartner ? {
    partnerAuthorization: {
      defaultMaximumExpirationTimeInDays: 7
      authorizedPartnersList: [
        {
          partnerRegistrationImmutableId: authorizedPartnerRegistrationImmutableId
          partnerName: authorizedPartnerName
        }
      ]
    }
  } : {}
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
        resourceId: functionResourceId
      }
    }
    eventDeliverySchema: 'EventGridSchema'
  }
}

output partnerConfigurationId string = partnerConfiguration.id
output partnerTopicEventSubscriptionId string = shouldCreatePartnerTopicSubscription ? partnerTopicEventSubscription.id : ''
