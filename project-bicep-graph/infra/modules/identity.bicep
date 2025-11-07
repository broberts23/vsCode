// Creates an application + service principal via Microsoft Graph Bicep beta extension.
// Docs:
// Applications: https://learn.microsoft.com/graph/templates/bicep/reference/applications?view=graph-bicep-beta
// Service Principals: https://learn.microsoft.com/graph/templates/bicep/reference/serviceprincipals?view=graph-bicep-beta
// IMPORTANT: Beta resources subject to change.

extension graphBeta

param prNumber int
param ttlHours int
@description('ISO8601 created timestamp for tagging')
param createdAt string = 'n/a'
@description('Optional list of existing test user UPNs to place into a generated security group for Swagger/API access.')
param testUserPrincipalNames array = []

// GUID seeds for deterministic scope & role identifiers (must be stable across redeploys for consent integrity)
var swaggerReadScopeId = guid(subscription().id, resourceGroup().id, 'Swagger.Read', string(prNumber))
var swaggerWriteScopeId = guid(subscription().id, resourceGroup().id, 'Swagger.Write', string(prNumber))
var swaggerAdminRoleId = guid(subscription().id, resourceGroup().id, 'Swagger.Admin', string(prNumber))

var uniqueSuffix = toLower(uniqueString(subscription().id, resourceGroup().id, string(prNumber)))
var displayBase = 'pr-${prNumber}-${uniqueSuffix}'

resource app 'Microsoft.Graph/applications@beta' = {
  displayName: 'app-${displayBase}'
  uniqueName: 'app-${displayBase}'
  signInAudience: 'AzureADMyOrg'
  groupMembershipClaims: 'SecurityGroup'
  api: {
    requestedAccessTokenVersion: 2
    oauth2PermissionScopes: [
      {
        adminConsentDescription: 'Read access to Swagger endpoints for PR ${prNumber}'
        adminConsentDisplayName: 'Swagger.Read'
        id: swaggerReadScopeId
        isEnabled: true
        type: 'User'
        userConsentDescription: 'Allow reading API documentation.'
        userConsentDisplayName: 'Read API docs'
        value: 'Swagger.Read'
      }
      {
        adminConsentDescription: 'Write access to Swagger endpoints for PR ${prNumber}'
        adminConsentDisplayName: 'Swagger.Write'
        id: swaggerWriteScopeId
        isEnabled: true
        type: 'Admin'
        userConsentDescription: 'Allow updating API documentation.'
        userConsentDisplayName: 'Write API docs'
        value: 'Swagger.Write'
      }
    ]
  }
  appRoles: [
    {
      allowedMemberTypes: [
        'User'
        'Application'
      ]
      description: 'Administrative access to Swagger management operations for PR ${prNumber}'
      displayName: 'Swagger Admin'
      id: swaggerAdminRoleId
      isEnabled: true
      value: 'Swagger.Admin'
    }
  ]
  tags: [
    'Env=pr-${prNumber}'
    'TTLHours=${ttlHours}'
    'CreatedAt=${createdAt}'
  ]
}

resource sp 'Microsoft.Graph/servicePrincipals@beta' = {
  appId: app.appId
  displayName: app.displayName
  tags: [
    'Env=pr-${prNumber}'
    'TTLHours=${ttlHours}'
    'CreatedAt=${createdAt}'
  ]
}

// Existing user references (creation of users via Graph Bicep currently limited; treat as existing)
resource testUsers 'Microsoft.Graph/users@beta' existing = [for upn in testUserPrincipalNames: {
  userPrincipalName: toLower(upn)
}]

// Security group to aggregate test users for role/scoped access (only if users provided)
resource testGroup 'Microsoft.Graph/groups@beta' = if (length(testUserPrincipalNames) > 0) {
  displayName: 'grp-${displayBase}-testers'
  uniqueName: 'grp-${displayBase}-testers'
  description: 'Ephemeral test access group for PR ${prNumber}'
  mailEnabled: false
  securityEnabled: true
  mailNickname: replace('grp${prNumber}${uniqueSuffix}', '-', '')
  members: {
    relationships: [for (upn, i) in testUserPrincipalNames: testUsers[i].id]
    relationshipSemantics: 'append'
  }
}

output appId string = app.appId
output appObjectId string = app.id
output servicePrincipalObjectId string = sp.id
output displayName string = app.displayName
@secure()
output swaggerScopes object = {
  read: swaggerReadScopeId
  write: swaggerWriteScopeId
}
@secure()
output swaggerAdminRoleId string = swaggerAdminRoleId
// Avoid referencing conditionally-deployed resource id directly; emit displayName for discovery instead.
output testGroupDisplayName string = length(testUserPrincipalNames) > 0 ? 'grp-${displayBase}-testers' : ''
