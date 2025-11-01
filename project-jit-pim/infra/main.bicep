// main.bicep - demo infra for JIT PIM project
// Minimal resources to demonstrate privileged operations. Replace or extend
// with your real demo resources.

param location string = resourceGroup().location
param storageAccountName string = 'pimdemosa${uniqueString(resourceGroup().id)}'

@description('Name of the user-assigned managed identity to create for demo automation')
param userAssignedIdentityName string = 'pimDemoIdentity${uniqueString(resourceGroup().id)}'

@description('Name of the Key Vault to create for the demo')
param keyVaultName string = toLower(substring('kv${uniqueString(resourceGroup().id)}', 0, 15))

resource storage 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: toLower(storageAccountName)
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
  }
}

// Create a user-assigned managed identity that can be used by automation.
resource userIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: toLower(userAssignedIdentityName)
  location: location
}

// Key Vault for storing secrets used in the demo. We grant the managed identity secret permissions.
resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: toLower(keyVaultName)
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    // Use RBAC permission model for Key Vault data plane so role assignments
    // can be managed via Azure RBAC / PIM. Access policies are ignored when
    // enableRbacAuthorization is true.
    enableRbacAuthorization: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableSoftDelete: true
  }
}

// Assign the built-in 'Key Vault Secrets Officer' role to the user-assigned managed identity
// scoped to the Key Vault resource. This allows the identity to set secrets in the vault.
// Role definition id for Key Vault Secrets Officer: b86a8fe4-44ce-4948-aee5-eccb2c155cd7
var keyVaultSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'

resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  // Use stable values for role assignment name GUID: subscriptionId, keyVault.id, and userIdentity.id
  name: guid(subscription().subscriptionId, keyVault.id, userIdentity.id, keyVaultSecretsOfficerRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRoleId)
    principalId: userIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs for wiring into CI and scripts
output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output userIdentityClientId string = userIdentity.properties.clientId
output userIdentityPrincipalId string = userIdentity.properties.principalId
output userIdentityResourceId string = userIdentity.id

// Outputs to help wiring up automation. In a production demo you'd create
// the assignable group and app registration via Graph / portal and record the IDs.
output storageAccountId string = storage.id
output storageAccountName string = storage.name
