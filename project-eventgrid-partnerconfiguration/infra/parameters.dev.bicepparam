using './main.bicep'

param location = 'centralindia'
param partnerConfigurationName = 'default'

// Partner authorization: omit these params to use main.bicep defaults
// (authorizedPartnerName = 'Microsoft Graph API', expiration = utcNow()+7 days).

// Optional: enable deployment-time bootstrap using a pre-created user-assigned managed identity
// param bootstrapUserAssignedIdentityName = '<uami-name-in-this-rg>'

// Optional: when bootstrap is enabled, set a partner topic name to be created/used by Graph
// param partnerTopicName = 'default'
