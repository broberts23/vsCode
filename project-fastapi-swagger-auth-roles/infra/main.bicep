targetScope = 'resourceGroup'

@description('Environment name')
@allowed(['dev', 'test', 'prod'])
param deploymentEnvironment string = 'dev'

@description('Azure region')
param location string = resourceGroup().location

@description('Base name for resources')
param baseName string = 'fsa'

@description('Optional ACR name. Leave empty to generate a unique name.')
param acrName string = ''

@description('Container image. Leave empty to deploy hello-world for the first pass.')
param containerImage string = ''

@description('Microsoft Entra tenant ID')
param tenantId string

@description('API app registration client ID (JWT audience / OpenAPI client)')
param apiClientId string

@description('OpenAPI / Swagger OAuth client ID (defaults to apiClientId)')
param openApiClientId string = ''

@description('Cosmos database id')
param cosmosDatabaseName string = 'identitydb'

@description('Cosmos container id')
param cosmosContainerName string = 'identities'

@description('Tags')
param tags object = {
  Environment: deploymentEnvironment
  Application: 'FastapiSwaggerAuthRoles'
  ManagedBy: 'Bicep'
}

var uniqueSuffix = take(uniqueString(resourceGroup().id, baseName, deploymentEnvironment), 6)
var effectiveAcrName = empty(acrName)
  ? toLower('${take(replace(baseName, '-', ''), 37)}acr${deploymentEnvironment}${uniqueSuffix}')
  : acrName
var cosmosName = toLower(take('${baseName}-cosmos-${deploymentEnvironment}-${uniqueSuffix}', 44))
var logAnalyticsName = '${baseName}-law-${deploymentEnvironment}-${uniqueSuffix}'
var envName = 'cae-${baseName}-${deploymentEnvironment}-${uniqueSuffix}'
var apiAppName = 'ca-${baseName}-api-${deploymentEnvironment}-${uniqueSuffix}'

var useCustomImage = !empty(containerImage)
var image = useCustomImage ? containerImage : 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
var targetPort = useCustomImage ? 8080 : 80
var effectiveOpenApiClientId = empty(openApiClientId) ? apiClientId : openApiClientId

// Built-in role definition IDs
var roleAcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
// Cosmos DB Built-in Data Contributor (data-plane SQL role)
var roleCosmosDataContributor = '00000000-0000-0000-0000-000000000002'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2026-03-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2025-11-01' = {
  name: effectiveAcrName
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2026-03-15' = {
  name: cosmosName
  location: location
  tags: tags
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    enableFreeTier: false
    capabilities: [
      { name: 'EnableServerless' }
    ]
    disableLocalAuth: true
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
  }
}

resource cosmosSqlDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2026-03-15' = {
  parent: cosmos
  name: cosmosDatabaseName
  properties: {
    resource: { id: cosmosDatabaseName }
  }
}

resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2026-03-15' = {
  parent: cosmosSqlDb
  name: cosmosContainerName
  properties: {
    resource: {
      id: cosmosContainerName
      partitionKey: {
        paths: ['/id']
        kind: 'Hash'
      }
    }
  }
}

resource containerEnv 'Microsoft.App/managedEnvironments@2026-07-01' = {
  name: envName
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

var appEnv = [
  {
    name: 'USE_COSMOS_EMULATOR'
    value: 'false'
  }
  {
    name: 'COSMOS_ENDPOINT'
    value: cosmos.properties.documentEndpoint
  }
  {
    name: 'COSMOS_DATABASE'
    value: cosmosDatabaseName
  }
  {
    name: 'COSMOS_CONTAINER'
    value: cosmosContainerName
  }
  {
    name: 'TENANT_ID'
    value: tenantId
  }
  {
    name: 'API_CLIENT_ID'
    value: apiClientId
  }
  {
    name: 'OPENAPI_CLIENT_ID'
    value: effectiveOpenApiClientId
  }
]

resource apiApp 'Microsoft.App/containerApps@2026-07-01' = {
  name: apiAppName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: targetPort
        transport: 'http'
        allowInsecure: false
      }
      registries: useCustomImage
        ? [
            {
              server: acr.properties.loginServer
              identity: 'system'
            }
          ]
        : []
    }
    template: {
      scale: {
        minReplicas: 0
        maxReplicas: 3
      }
      containers: [
        {
          name: 'api'
          image: image
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: appEnv
        }
      ]
    }
  }
}

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, apiApp.id, roleAcrPull)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
    principalId: apiApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource cosmosDataRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2026-03-15' = {
  parent: cosmos
  name: guid(cosmos.id, apiApp.id, roleCosmosDataContributor)
  properties: {
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/${roleCosmosDataContributor}'
    principalId: apiApp.identity.principalId
    scope: cosmos.id
  }
}

output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output containerAppsEnvironmentName string = containerEnv.name
output apiAppName string = apiApp.name
output apiFqdn string = apiApp.properties.configuration.ingress.fqdn
output cosmosEndpoint string = cosmos.properties.documentEndpoint
output cosmosDatabase string = cosmosDatabaseName
output cosmosContainer string = cosmosContainerName
output managedIdentityPrincipalId string = apiApp.identity.principalId
output deployedImage string = image
