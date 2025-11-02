// main.bicep - demo infra for JIT PIM project
// Minimal resources to demonstrate privileged operations. Replace or extend
// with your real demo resources.

param location string = resourceGroup().location
param storageAccountName string = 'pimdemosa${uniqueString(resourceGroup().id)}'

// Import the Microsoft Graph Bicep extension so `Microsoft.Graph/*` resource types
// are recognized. This requires a recent Bicep CLI and the `extensibility` experimental
// feature enabled in bicepconfig.json (see bicep docs / issue discussion).
extension graphV1
extension graphBeta

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

// Assumption: the built-in User Access Administrator role definition ID used here grants permission
// to create/remove role assignments. Adjust roleDefinitionId and scope as required for your security model.
var userAccessAdminRoleId = '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' // User Access Administrator (assumed)

// Use Microsoft.Graph Bicep resources. These use the Graph provider and expose
// application and servicePrincipal properties at the top level in the template.
// See: https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta
resource ghApp 'Microsoft.Graph/applications@beta' = {
  uniqueName: toLower('pim-github-app-${uniqueString(resourceGroup().id)}')
  displayName: 'pim-github-oidc-app-${uniqueString(resourceGroup().id)}'
  signInAudience: 'AzureADMyOrg'
}

resource ghSp 'Microsoft.Graph/servicePrincipals@beta' = {
  appId: ghApp.appId
  displayName: ghApp.displayName
}

// Resource-group scoped role assignment to allow the SP to create/remove RBAC assignments at this RG level.
// Using the resource group scope keeps the template deployable without cross-scope modules. Adjust scope
// if you need subscription-wide permissions (then deploy a separate subscription-scoped module).
resource ghSpRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, resourceGroup().id, 'ghSpRole', userAccessAdminRoleId)
  scope: resourceGroup()
  properties: {
    // roleDefinitionId expects the full resource id for the role definition. Role definitions live under
    // the subscription scope, so build the subscription-level resource id for the role definition.
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', userAccessAdminRoleId)
    principalId: ghSp.id
    principalType: 'ServicePrincipal'
  }
}

// Key Vault for storing secrets used in the demo. We grant the managed identity secret permissions.
resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
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

// Outputs for wiring into CI and scripts
output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output userIdentityClientId string = userIdentity.properties.clientId
output userIdentityPrincipalId string = userIdentity.properties.principalId
output userIdentityResourceId string = userIdentity.id

// Outputs for the GitHub OIDC app/service-principal created in this template.
output githubAppId string = ghApp.appId
output githubServicePrincipalId string = ghSp.id
output githubServicePrincipalResourceId string = ghSp.id

// Outputs to help wiring up automation. In a production demo you'd create
// the assignable group and app registration via Graph / portal and record the IDs.
output storageAccountId string = storage.id
output storageAccountName string = storage.name
