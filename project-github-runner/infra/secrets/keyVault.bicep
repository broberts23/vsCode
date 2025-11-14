// Module: Creates an Azure Key Vault with RBAC authorization enabled.

@description('Name of the Key Vault (3-24 characters, alphanumeric).')
param name string

@description('Azure region for the Key Vault.')
param location string

@description('Tags applied to the Key Vault resource.')
param tags object = {}

resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    enableRbacAuthorization: true
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

output name string = keyVault.name
output id string = keyVault.id
