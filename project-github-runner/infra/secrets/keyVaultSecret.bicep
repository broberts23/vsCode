// Module: Creates or updates a secret in an existing Key Vault.

@description('Tags applied to the Key Vault secret.')
param tags object = {}

@description('Name of the target Key Vault.')
param vaultName string

@description('Name of the secret to create or update.')
param secretName string

@description('Value of the secret stored in the Key Vault.')
@secure()
param secretValue string

resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' existing = {
  name: vaultName
}

resource keyVaultSecret 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  name: secretName
  parent: keyVault
  tags: tags
  properties: {
    value: secretValue
  }
}

output uri string = keyVaultSecret.properties.secretUri
