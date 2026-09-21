targetScope = 'resourceGroup'

@description('Environment name')
@allowed(['dev', 'test', 'prod'])
param deploymentEnvironment string = 'dev'

@description('Azure region')
param location string = resourceGroup().location

@description('Base name for resources')
param baseName string = 'ara'

@description('Microsoft Entra tenant ID (OIDC SPA/API)')
param tenantId string

@description('API app registration client ID (audience validation)')
param apiClientId string = ''

@description('SPA app registration client ID')
param spaClientId string = ''

@description('API audience, e.g. api://access-reviews-autopilot')
param apiAudience string = 'api://access-reviews-autopilot'

@description('Container image (ACR). Leave empty to deploy infra only.')
param containerImage string = ''

@description('Tags')
param tags object = {
  Environment: deploymentEnvironment
  Application: 'AccessReviewsAutopilot'
  ManagedBy: 'Bicep'
}

var uniqueSuffix = take(uniqueString(resourceGroup().id, baseName, deploymentEnvironment), 6)
var acrName = toLower('${take(replace(baseName, '-', ''), 37)}acr${deploymentEnvironment}${uniqueSuffix}')
var cosmosName = toLower(take('${baseName}-cosmos-${deploymentEnvironment}-${uniqueSuffix}', 44))
var sbName = toLower(take('${baseName}-sb-${deploymentEnvironment}-${uniqueSuffix}', 50))
var kvName = toLower(take('${baseName}-kv-${uniqueSuffix}', 24))
var appConfigName = '${take('${baseName}-appcs-${deploymentEnvironment}-', 44)}${uniqueSuffix}'
var appInsightsName = '${baseName}-appi-${deploymentEnvironment}-${uniqueSuffix}'
var logAnalyticsName = '${baseName}-law-${deploymentEnvironment}-${uniqueSuffix}'
var identityName = 'id-${baseName}-${deploymentEnvironment}-${uniqueSuffix}'
var envName = 'cae-${baseName}-${deploymentEnvironment}-${uniqueSuffix}'
var apiAppName = 'ca-${baseName}-api-${deploymentEnvironment}-${uniqueSuffix}'
var workerNotifyName = 'ca-${baseName}-notify-${deploymentEnvironment}-${uniqueSuffix}'
var workerApplyName = 'ca-${baseName}-apply-${deploymentEnvironment}-${uniqueSuffix}'
var simJobName = 'caj-${baseName}-sim-${deploymentEnvironment}-${uniqueSuffix}'

// Built-in role definition IDs
var roleAcrPull = '7f951dda-4ed3-4680-a7ca-43fe172d538d'
var roleSbDataOwner = '090c5cfd-751d-490a-894a-3ce6f1109419'
var roleKvSecretsUser = '4633458b-17de-408a-b874-04405c546301'
var roleAppConfigDataReader = '516239f1-63e1-4d78-a4de-a74fb236a071'
var roleMonitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'
// Cosmos DB Built-in Data Contributor
var roleCosmosDataContributor = '00000000-0000-0000-0000-000000000002'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = {
  name: identityName
  location: location
  tags: tags
}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2026-03-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    RetentionInDays: 30
  }
}

resource acr 'Microsoft.ContainerRegistry/registries@2025-11-01' = {
  name: acrName
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, identity.id, roleAcrPull)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAcrPull)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
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
    disableKeyBasedMetadataWriteAccess: true
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
  }
}

resource cosmosSqlDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2026-03-15' = {
  parent: cosmos
  name: 'ara'
  properties: {
    resource: { id: 'ara' }
  }
}

resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2026-03-15' = {
  parent: cosmosSqlDb
  name: 'correlations'
  properties: {
    resource: {
      id: 'correlations'
      partitionKey: {
        paths: ['/partition_key']
        kind: 'Hash'
      }
      defaultTtl: 2592000
    }
  }
}

// Cosmos data-plane RBAC (SQL role assignment)
resource cosmosDataRole 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2026-03-15' = {
  parent: cosmos
  name: guid(cosmos.id, identity.id, roleCosmosDataContributor)
  properties: {
    roleDefinitionId: '${cosmos.id}/sqlRoleDefinitions/${roleCosmosDataContributor}'
    principalId: identity.properties.principalId
    scope: cosmos.id
  }
}

resource serviceBus 'Microsoft.ServiceBus/namespaces@2026-01-01' = {
  name: sbName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
  properties: {
    disableLocalAuth: true
    minimumTlsVersion: '1.2'
  }
}

resource sbTopic 'Microsoft.ServiceBus/namespaces/topics@2026-01-01' = {
  parent: serviceBus
  name: 'review-work'
  properties: {
    defaultMessageTimeToLive: 'P14D'
    requiresDuplicateDetection: false
  }
}

resource sbSubNotify 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2026-01-01' = {
  parent: sbTopic
  name: 'slack-notify'
  properties: {
    maxDeliveryCount: 5
    deadLetteringOnMessageExpiration: true
    lockDuration: 'PT1M'
  }
}

resource sbSubNotifyRule 'Microsoft.ServiceBus/namespaces/topics/subscriptions/rules@2026-01-01' = {
  parent: sbSubNotify
  name: '$Default'
  properties: {
    filterType: 'SqlFilter'
    sqlFilter: {
      sqlExpression: 'sys.Subject <> \'ApplyDecision\''
    }
  }
}

resource sbSubApply 'Microsoft.ServiceBus/namespaces/topics/subscriptions@2026-01-01' = {
  parent: sbTopic
  name: 'apply-decision'
  properties: {
    maxDeliveryCount: 5
    deadLetteringOnMessageExpiration: true
    lockDuration: 'PT1M'
  }
}

resource sbSubApplyRule 'Microsoft.ServiceBus/namespaces/topics/subscriptions/rules@2026-01-01' = {
  parent: sbSubApply
  name: '$Default'
  properties: {
    filterType: 'SqlFilter'
    sqlFilter: {
      sqlExpression: 'sys.Subject = \'ApplyDecision\''
    }
  }
}

resource sbDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(serviceBus.id, identity.id, roleSbDataOwner)
  scope: serviceBus
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleSbDataOwner)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2026-02-01' = {
  name: kvName
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, identity.id, roleKvSecretsUser)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleKvSecretsUser)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource appConfig 'Microsoft.AppConfiguration/configurationStores@2024-06-01' = {
  name: appConfigName
  location: location
  tags: tags
  sku: { name: 'Free' }
  properties: {
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
  }
}

resource appConfigReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appConfig.id, identity.id, roleAppConfigDataReader)
  scope: appConfig
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleAppConfigDataReader)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource metricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, identity.id, roleMonitoringMetricsPublisher)
  scope: appInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleMonitoringMetricsPublisher)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource containerEnv 'Microsoft.App/managedEnvironments@2026-01-01' = {
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

var sharedEnv = [
  {
    name: 'ARA_ENVIRONMENT'
    value: deploymentEnvironment
  }
  {
    name: 'ARA_AUTH_BYPASS'
    value: 'false'
  }
  {
    name: 'AZURE_CLIENT_ID'
    value: identity.properties.clientId
  }
  {
    name: 'COSMOS_ENDPOINT'
    value: cosmos.properties.documentEndpoint
  }
  {
    name: 'COSMOS_DATABASE'
    value: 'ara'
  }
  {
    name: 'COSMOS_CONTAINER'
    value: 'correlations'
  }
  {
    name: 'SERVICE_BUS_FULLY_QUALIFIED_NAMESPACE'
    value: '${serviceBus.name}.servicebus.windows.net'
  }
  {
    name: 'SERVICE_BUS_TOPIC'
    value: 'review-work'
  }
  {
    name: 'SERVICE_BUS_SUBSCRIPTION_NOTIFY'
    value: 'slack-notify'
  }
  {
    name: 'SERVICE_BUS_SUBSCRIPTION_APPLY'
    value: 'apply-decision'
  }
  {
    name: 'KEY_VAULT_URI'
    value: keyVault.properties.vaultUri
  }
  {
    name: 'ENTRA_TENANT_ID'
    value: tenantId
  }
  {
    name: 'ENTRA_API_CLIENT_ID'
    value: apiClientId
  }
  {
    name: 'ENTRA_SPA_CLIENT_ID'
    value: spaClientId
  }
  {
    name: 'ENTRA_API_AUDIENCE'
    value: apiAudience
  }
  {
    name: 'ENTRA_REQUIRED_SCOPE'
    value: 'access_as_user'
  }
  {
    name: 'FIXTURES_DIR'
    value: '/app/config/simulated-events'
  }
  {
    name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
    value: appInsights.properties.ConnectionString
  }
]

var image = empty(containerImage) ? 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest' : containerImage
var deployRealApps = !empty(containerImage)

resource apiApp 'Microsoft.App/containerApps@2026-01-01' = if (deployRealApps) {
  name: apiAppName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
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
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: sharedEnv
          command: ['uvicorn', 'api.main:app', '--host', '0.0.0.0', '--port', '8080']
        }
      ]
    }
  }
}

resource workerNotify 'Microsoft.App/containerApps@2026-01-01' = if (deployRealApps) {
  name: workerNotifyName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
    }
    template: {
      scale: {
        minReplicas: 0
        maxReplicas: 5
        rules: [
          {
            name: 'sb-notify'
            custom: {
              type: 'azure-servicebus'
              metadata: {
                namespace: serviceBus.name
                topicName: 'review-work'
                subscriptionName: 'slack-notify'
                messageCount: '1'
              }
              identity: identity.id
            }
          }
        ]
      }
      containers: [
        {
          name: 'worker'
          image: image
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: sharedEnv
          command: ['python', '-m', 'worker.main', '--mode', 'notify']
        }
      ]
    }
  }
}

resource workerApply 'Microsoft.App/containerApps@2026-01-01' = if (deployRealApps) {
  name: workerApplyName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
    }
    template: {
      scale: {
        minReplicas: 0
        maxReplicas: 5
        rules: [
          {
            name: 'sb-apply'
            custom: {
              type: 'azure-servicebus'
              metadata: {
                namespace: serviceBus.name
                topicName: 'review-work'
                subscriptionName: 'apply-decision'
                messageCount: '1'
              }
              identity: identity.id
            }
          }
        ]
      }
      containers: [
        {
          name: 'worker'
          image: image
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: sharedEnv
          command: ['python', '-m', 'worker.main', '--mode', 'apply']
        }
      ]
    }
  }
}

resource simulatorJob 'Microsoft.App/jobs@2026-01-01' = if (deployRealApps) {
  name: simJobName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    environmentId: containerEnv.id
    configuration: {
      triggerType: 'Schedule'
      scheduleTriggerConfig: {
        cronExpression: '0 */6 * * *'
        parallelism: 1
        replicaCompletionCount: 1
      }
      replicaTimeout: 300
      replicaRetryLimit: 1
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'simulator'
          image: image
          resources: { cpu: json('0.25'), memory: '0.5Gi' }
          env: sharedEnv
          command: ['python', '-m', 'simulator.main']
        }
      ]
    }
  }
}

output acrLoginServer string = acr.properties.loginServer
output cosmosEndpoint string = cosmos.properties.documentEndpoint
output serviceBusNamespace string = '${serviceBus.name}.servicebus.windows.net'
output keyVaultUri string = keyVault.properties.vaultUri
output appConfigEndpoint string = appConfig.properties.endpoint
output managedIdentityClientId string = identity.properties.clientId
output managedIdentityPrincipalId string = identity.properties.principalId
output containerAppsEnvironmentId string = containerEnv.id
output apiFqdn string = deployRealApps ? apiApp!.properties.configuration.ingress.fqdn : ''
output appInsightsConnectionString string = appInsights.properties.ConnectionString
