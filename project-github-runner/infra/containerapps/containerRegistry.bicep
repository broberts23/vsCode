// Module: Azure Container Registry
// Reference: https://learn.microsoft.com/azure/container-registry/container-registry-intro

param name string
param location string
@allowed([
  'Basic'
  'Standard'
  'Premium'
])
param sku string = 'Basic'
param adminUserEnabled bool = false
param tags object = {}

@description('Optional principal to grant AcrPull permissions to (e.g. user-assigned managed identity).')
param principalId string = ''
@allowed([
  'ServicePrincipal'
  'User'
  'Group'
  'ForeignGroup'
])
param principalType string = 'ServicePrincipal'

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: sku
  }
  properties: {
    adminUserEnabled: adminUserEnabled
    publicNetworkAccess: 'Enabled'
  }
}

var acrPullRoleId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(registry.id, principalId, acrPullRoleId)
  scope: registry
  properties: {
    roleDefinitionId: acrPullRoleId
    principalId: principalId
    principalType: principalType
  }
}

output registryId string = registry.id
output loginServer string = registry.properties.loginServer
