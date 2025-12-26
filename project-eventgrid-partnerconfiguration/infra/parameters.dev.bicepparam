using './main.bicep'

param location = 'centralindia'
param partnerConfigurationName = 'default'

// Optional: authorization entry (leave empty to manage out-of-band)
param authorizedPartnerRegistrationImmutableId = 'c02e0126-707c-436d-b6a1-175d2748fb58'
param authorizedPartnerName = 'MicrosoftGraphAPI'
param authorizedPartnerAuthorizationExpirationTimeInUtc = ''

// Optional: route an existing partner topic to a Function
param partnerTopicName = 'default'
param partnerTopicEventSubscriptionName = 'to-governance-function'
param functionResourceId = ''
