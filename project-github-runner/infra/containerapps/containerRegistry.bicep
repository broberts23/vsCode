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

resource registry 'Microsoft.ContainerRegistry/registries@2025-04-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: sku
  }
  properties: {
    adminUserEnabled: adminUserEnabled
    publicNetworkAccess: 'Enabled'
    policies: {
      azureADAuthenticationAsArmPolicy: {
        status: 'Enabled'
      }
    }
  }
}

output registryId string = registry.id
output loginServer string = registry.properties.loginServer
