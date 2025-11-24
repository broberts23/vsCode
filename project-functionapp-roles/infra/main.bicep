targetScope = 'resourceGroup'

// ====================================
// Parameters
// ====================================

@description('Environment name (dev, test, prod)')
@allowed(['dev', 'test', 'prod'])
param environment string = 'dev'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Base name for all resources')
param baseName string = 'pwdreset'

@description('Tags to apply to all resources')
param tags object = {
  Environment: environment
  Application: 'PasswordReset'
  ManagedBy: 'Bicep'
}

@description('Entra ID Tenant ID')
param tenantId string

@description('Expected JWT audience (Application ID)')
param expectedAudience string

@description('Required role claim for password reset')
param requiredRole string = 'Role.PasswordReset'

@description('AD service account username (e.g., DOMAIN\\svc-pwdreset)')
@secure()
param adServiceAccountUsername string

@description('AD service account password')
@secure()
param adServiceAccountPassword string

@description('Domain controller FQDN (optional)')
param domainController string = ''

// ====================================
// Variables
// ====================================

var uniqueSuffix = uniqueString(resourceGroup().id, baseName)
var functionAppName = '${baseName}-func-${environment}-${uniqueSuffix}'
var appServicePlanName = '${baseName}-asp-${environment}-${uniqueSuffix}'
var storageAccountName = '${baseName}st${environment}${take(uniqueSuffix, 8)}'
var keyVaultName = '${baseName}-kv-${environment}-${take(uniqueSuffix, 8)}'
var logAnalyticsName = '${baseName}-log-${environment}-${uniqueSuffix}'
var appInsightsName = '${baseName}-ai-${environment}-${uniqueSuffix}'

// ====================================
// Resources
// ====================================

// Log Analytics Workspace
// https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

// Application Insights
// https://learn.microsoft.com/azure/azure-monitor/app/app-insights-overview
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspace.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Storage Account for Function App
// https://learn.microsoft.com/azure/storage/common/storage-account-overview
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Key Vault
// https://learn.microsoft.com/azure/key-vault/general/overview
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// Key Vault Secret for AD Service Account
// https://learn.microsoft.com/azure/key-vault/secrets/about-secrets
resource adServiceAccountSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'ENTRA-PWDRESET-RW'
  properties: {
    value: '{"username":"${adServiceAccountUsername}","password":"${adServiceAccountPassword}"}'
    contentType: 'application/json'
    attributes: {
      enabled: true
    }
  }
}

// App Service Plan (Linux Consumption)
// https://learn.microsoft.com/azure/app-service/overview-hosting-plans
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  kind: 'functionapp'
  properties: {
    reserved: true // Linux
  }
}

// Function App with Managed Identity
// https://learn.microsoft.com/azure/azure-functions/functions-overview
resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    reserved: true
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'PowerShell|7.4'
      powerShellVersion: '7.4'
      use32BitWorkerProcess: false
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      functionAppScaleLimit: 200
      minimumElasticInstanceCount: 0
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME_VERSION'
          value: '7.4'
        }
        {
          name: 'FUNCTIONS_WORKER_PROCESS_COUNT'
          value: '2'
        }
        {
          name: 'PSWorkerInProcConcurrencyUpperBound'
          value: '10'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppName)
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'TENANT_ID'
          value: tenantId
        }
        {
          name: 'EXPECTED_AUDIENCE'
          value: expectedAudience
        }
        {
          name: 'EXPECTED_ISSUER'
          value: 'https://sts.windows.net/${tenantId}/'
        }
        {
          name: 'REQUIRED_ROLE'
          value: requiredRole
        }
        {
          name: 'KEY_VAULT_URI'
          value: keyVault.properties.vaultUri
        }
        {
          name: 'DOMAIN_CONTROLLER'
          value: domainController
        }
      ]
    }
  }
  dependsOn: [
    adServiceAccountSecret
  ]
}

// Key Vault Secrets Officer role assignment for Function App
// https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#key-vault-secrets-officer
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'
    ) // Key Vault Secrets User
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ====================================
// Outputs
// ====================================

@description('Function App name')
output functionAppName string = functionApp.name

@description('Function App hostname')
output functionAppHostName string = functionApp.properties.defaultHostName

@description('Function App Managed Identity Principal ID')
output functionAppPrincipalId string = functionApp.identity.principalId

@description('Function App resource ID')
output functionAppResourceId string = functionApp.id

@description('Key Vault name')
output keyVaultName string = keyVault.name

@description('Key Vault URI')
output keyVaultUri string = keyVault.properties.vaultUri

@description('Application Insights Instrumentation Key')
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey

@description('Application Insights Connection String')
output appInsightsConnectionString string = appInsights.properties.ConnectionString

@description('Storage Account name')
output storageAccountName string = storageAccount.name

@description('Log Analytics Workspace ID')
output logAnalyticsWorkspaceId string = logAnalyticsWorkspace.id
