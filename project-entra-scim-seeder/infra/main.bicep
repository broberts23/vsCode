// infra/main.bicep
//
// Deploys the Azure resources required by the entra-scim-seeder SCIM gateway:
//   - User-Assigned Managed Identity (free)
//   - Key Vault, Standard (cheapest; RBAC authorization)
//   - Container Registry, Basic (cheapest ACR SKU)
//   - Cosmos DB (free tier enabled when available)
//   - Log Analytics, PerGB2018 (cheapest; first 5GB/mo free)
//   - Container Apps Environment (Consumption)
//   - Container App (Consumption - 180k vCPU-s / 2M req free/mo)
//   - RBAC role assignments for keyless (Managed Identity) access
//
// Deploy (resource-group scope, assumes RG already exists):
//   az deployment group create -g <rg> -f infra/main.bicep \
//     -p imageName=<acr>.azurecr.io/scim-gateway:v1
//
// After deployment, retrieve the SCIM bearer token:
//   az keyvault secret show --vault-name <kv> -n scim-bearer-token --query value -o tsv

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

@description('Base name used for all resources (lowercase, max 12 chars for Cosmos). Must be globally unique suffix.')
param baseName string

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Container image to deploy. Defaults to <acr>/scim-gateway:v1.')
param imageName string = ''

@description('Enable Cosmos DB free tier (1000 RU/s + 5GB). One per subscription.')
param enableCosmosFreeTier bool = true

@description('Name of the Key Vault secret holding the SCIM bearer token.')
param scimBearerTokenSecretName string = 'scim-bearer-token'

@description('Cosmos database and container names used by the gateway.')
param cosmosDatabaseName string = 'scim-db'
param cosmosContainerName string = 'users'

@description('Container App ingress external visibility. Use external=true for Entra SCIM reachability.')
param externalIngress bool = true

@description('Admin user object ID to grant Key Vault Secrets Officer for secret management (optional).')
param adminUserObjectId string = ''

// ---------------------------------------------------------------------------
// Well-known role definition GUIDs
// ---------------------------------------------------------------------------

var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
var keyVaultSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' // Key Vault Secrets Officer
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d' // AcrPull
var cosmosDbBuiltInDataContributorRoleId = '00000000-0000-0000-0000-000000000002' // Cosmos DB Built-in Data Contributor

// ---------------------------------------------------------------------------
// User-Assigned Managed Identity
// ---------------------------------------------------------------------------

resource scimMi 'Microsoft.ManagedIdentity/userAssignedIdentities@2025-05-31-preview' = {
  name: 'mi-scim-${baseName}'
  location: location
}

// ---------------------------------------------------------------------------
// Key Vault (Standard, RBAC authorization - no access policies)
// ---------------------------------------------------------------------------

resource keyVault 'Microsoft.KeyVault/vaults@2026-02-01' = {
  name: 'kv-${baseName}'
  location: location
  properties: {
    sku: {
      name: 'standard'
      family: 'A'
    }
    enableRbacAuthorization: true
    enableSoftDelete: false
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
    publicNetworkAccess: 'enabled'
    tenantId: subscription().tenantId
  }
}

// Pre-create the SCIM bearer token secret (deterministic GUID value).
// The deploying principal / adminUserObjectId needs Key Vault Secrets Officer.
resource scimBearerSecret 'Microsoft.KeyVault/vaults/secrets@2026-02-01' = {
  name: scimBearerTokenSecretName
  parent: keyVault
  properties: {
    value: guid(baseName, 'scim-token', subscription().id)
  }
}

// ---------------------------------------------------------------------------
// Azure Container Registry (Basic)
// ---------------------------------------------------------------------------

resource acr 'Microsoft.ContainerRegistry/registries@2025-11-01' = {
  name: 'acr${baseName}'
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'enabled'
  }
}

// ---------------------------------------------------------------------------
// Cosmos DB (SQL API, free tier is one-per-subscription)
// ---------------------------------------------------------------------------

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2026-03-15' = {
  name: 'cosmos-${baseName}'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    enableFreeTier: enableCosmosFreeTier
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
      maxIntervalInSeconds: 5
      maxStalenessPrefix: 100
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    publicNetworkAccess: 'enabled'
    enableAutomaticFailover: false
    enableMultipleWriteLocations: false
    minimalTlsVersion: 'Tls12'
  }
}

resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2026-03-15' = {
  name: cosmosDatabaseName
  parent: cosmos
  properties: {
    resource: { id: cosmosDatabaseName }
    options: enableCosmosFreeTier ? {} : { throughput: 400 }
  }
}

resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2026-03-15' = {
  name: cosmosContainerName
  parent: cosmosDb
  properties: {
    resource: {
      id: cosmosContainerName
      partitionKey: { paths: ['/userName'], kind: 'Hash' }
      indexingPolicy: {
        indexingMode: 'consistent'
        includedPaths: [{ path: '/*' }]
        excludedPaths: [{ path: '/"_etag"/?' }]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Log Analytics Workspace (PerGB2018 - cheapest)
// ---------------------------------------------------------------------------

resource law 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: 'law-${baseName}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ---------------------------------------------------------------------------
// Container Apps Environment (Consumption)
// ---------------------------------------------------------------------------

resource cae 'Microsoft.App/managedEnvironments@2026-01-01' = {
  name: 'cae-${baseName}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: law.properties.customerId
        sharedKey: law.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

// ---------------------------------------------------------------------------
// Container App (Consumption)
// ---------------------------------------------------------------------------

resource containerApp 'Microsoft.App/containerApps@2026-01-01' = {
  name: 'ca-scim-${baseName}'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${scimMi.id}': {}
    }
  }
  properties: {
    environmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: externalIngress
        targetPort: 8000
        transport: 'http'
        allowInsecure: false
        traffic: [
          {
            weight: 100
            latestRevision: true
          }
        ]
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: scimMi.id
        }
      ]
      secrets: [
        {
          name: 'scim-bearer-token'
          identity: scimMi.id
          keyVaultUrl: scimBearerSecret.properties.secretUri
        }
      ]
      identitySettings: [
        {
          identity: scimMi.id
          lifecycle: 'Main'
        }
      ]
    }
    template: {
      revisionSuffix: ''
      scale: {
        minReplicas: 0 // scale-to-zero: free when idle
        maxReplicas: 1
      }
      containers: [
        {
          name: 'scim-gateway'
          env: [
            { name: 'KEY_VAULT_URL', value: keyVault.properties.vaultUri }
            { name: 'SCIM_BEARER_TOKEN_SECRET_NAME', value: scimBearerTokenSecretName }
            { name: 'COSMOS_ENDPOINT', value: cosmos.properties.documentEndpoint }
            { name: 'SCIM_COSMOS_DATABASE_NAME', value: cosmosDatabaseName }
            { name: 'SCIM_COSMOS_CONTAINER_NAME', value: cosmosContainerName }
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
        }
      ]
    }
  }
}

// ---------------------------------------------------------------------------
// RBAC Role Assignments (keyless access via Managed Identity)
// ---------------------------------------------------------------------------

// MI -> Key Vault Secrets User (read SCIM bearer token at runtime)
resource raMiKeyVault 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(scimMi.name, keyVault.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: scimMi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// MI -> Cosmos DB Built-in Data Contributor (keyless Cosmos CRUD)
resource cosmosDBRoleAssignment 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2026-03-15' = {
  name: guid(scimMi.name, cosmosDb.id, cosmosDbBuiltInDataContributorRoleId)
  parent: cosmos
  properties: {
    principalId: scimMi.properties.principalId
    roleDefinitionId: subscriptionResourceId(
      'resourceGroups/${resourceGroup().name}/providers/Microsoft.DocumentDB/databaseAccounts/${cosmos.name}/sqlRoleDefinitions',
      cosmosDbBuiltInDataContributorRoleId
    )
    scope: '/'
  }
}

// MI -> AcrPull (pull container image)
resource raMiAcr 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(scimMi.name, acr.id, acrPullRoleId)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalId: scimMi.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Optional: admin user -> Key Vault Secrets Officer (to manage/rotate the token)
resource raAdminKv 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(adminUserObjectId)) {
  name: guid(adminUserObjectId, keyVault.id, keyVaultSecretsOfficerRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRoleId)
    principalId: adminUserObjectId
    principalType: 'User'
  }
}

// ---------------------------------------------------------------------------
// Outputs (.env-ready)
// ---------------------------------------------------------------------------

@description('Microsoft Entra tenant ID - use as TENANT_ID')
output tenantId string = subscription().tenantId

@description('Managed Identity client ID - use as CLIENT_ID (for keyless gateway runtime)')
output managedIdentityClientId string = scimMi.properties.clientId

@description('Managed Identity principal ID (object ID)')
output managedIdentityPrincipalId string = scimMi.properties.principalId

@description('Key Vault URI - use as KEY_VAULT_URL')
output keyVaultUrl string = keyVault.properties.vaultUri

@description('Key Vault name (for az CLI secret retrieval)')
output keyVaultName string = keyVault.name

@description('SCIM bearer token secret name - use as SCIM_BEARER_TOKEN_SECRET_NAME')
output scimBearerTokenSecretName string = scimBearerTokenSecretName

@description('Cosmos DB endpoint - use as COSMOS_ENDPOINT')
output cosmosEndpoint string = cosmos.properties.documentEndpoint

@description('Cosmos database name - use as SCIM_COSMOS_DATABASE_NAME')
output cosmosDatabaseName string = cosmosDatabaseName

@description('Cosmos container name - use as SCIM_COSMOS_CONTAINER_NAME')
output cosmosContainerName string = cosmosContainerName

@description('Container Registry login server (push images here)')
output acrLoginServer string = acr.properties.loginServer

@description('Container App FQDN (set as Entra Provisioning Tenant URL: https://<fqdn>/scim/v2)')
output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn

@description('Full SCIM endpoint URL for Entra Enterprise App provisioning')
output scimEndpointUrl string = 'https://${containerApp.properties.configuration.ingress.fqdn}/scim/v2'

@description('Command to retrieve the SCIM bearer token value (paste into Entra Secret Token field)')
output retrieveBearerTokenCommand string = 'az keyvault secret show --vault-name ${keyVault.name} -n ${scimBearerTokenSecretName} --query value -o tsv'
