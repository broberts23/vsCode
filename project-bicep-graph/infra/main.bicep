// Orchestrator template for per-PR ephemeral environment.
// Imports Graph extensions configured in bicepconfig.json (extensibility enabled).
// Preview feature: Microsoft Graph Bicep beta resources are subject to change.

param prNumber int
param location string = resourceGroup().location
param ttlHours int = 6
// Provide a createdAt timestamp as a parameter (consumer supplies value at deploy time if needed)
@description('ISO8601 timestamp for resource tagging (provide from workflow).')
param createdAt string = 'n/a'

// Module: Identity (App + Service Principal)
module identity 'modules/identity.bicep' = {
  name: 'identity-pr-${prNumber}'
  params: {
    prNumber: prNumber
      ttlHours: ttlHours
    createdAt: createdAt
  }
}

// Module: App Infra (Key Vault, Storage, Role Assignments)
module appInfra 'modules/appInfra.bicep' = {
  name: 'infra-pr-${prNumber}'
  params: {
    prNumber: prNumber
      location: location
    servicePrincipalObjectId: identity.outputs.servicePrincipalObjectId
    createdAt: createdAt
    appId: identity.outputs.appId
  }
}

// Placeholder outputs aggregating modules.
output appId string = identity.outputs.appId
output appObjectId string = identity.outputs.appObjectId
output servicePrincipalObjectId string = identity.outputs.servicePrincipalObjectId
output ttlHoursOut int = ttlHours
output prTag string = 'pr-${prNumber}'
output createdAtOut string = createdAt
output webAppUrl string = appInfra.outputs.webAppUrl
output webAppName string = appInfra.outputs.webAppName
output keyVaultName string = appInfra.outputs.keyVaultName
output storageAccountName string = appInfra.outputs.storageAccountName
@secure()
output swaggerScopes object = identity.outputs.swaggerScopes
@secure()
output swaggerAdminRoleId string = identity.outputs.swaggerAdminRoleId
output testGroupDisplayName string = identity.outputs.testGroupDisplayName

// Federation step (if implemented in Bicep later) would be an additional module.
// For now rely on scripts/GraphFederation.ps1 using Graph REST API.
