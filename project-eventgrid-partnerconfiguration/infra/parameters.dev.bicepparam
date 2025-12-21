using './main.bicep'

param location = 'westeurope'
param partnerConfigurationName = 'default'

// Optional: authorization entry (leave empty to manage out-of-band)
param authorizedPartnerRegistrationImmutableId = ''
param authorizedPartnerName = ''

// Optional: route an existing partner topic to a Function
param partnerTopicName = ''
param partnerTopicEventSubscriptionName = 'to-governance-function'
param functionResourceId = ''
