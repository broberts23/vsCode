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

@description('App Registration Client ID (Application ID) for authentication')
param clientId string

@description('Required role claim for password reset')
param requiredRole string = 'Role.PasswordReset'

@description('AD service account username (e.g., DOMAIN\\svc-pwdreset). Auto-generated when deployDomainController is true.')
@secure()
param adServiceAccountUsername string = ''

@description('AD service account password. Auto-generated from ServiceAccountPassword when deployDomainController is true.')
@secure()
param adServiceAccountPassword string = ''

@description('Service account password for domain controller deployment (used for both DC post-config and AD service account)')
@secure()
param serviceAccountPassword string = ''

@description('Domain controller FQDN (optional)')
param domainController string = ''

@description('VM admin username for domain controller')
param vmAdminUsername string = 'azureadmin'

@description('VM admin password for domain controller')
@secure()
param vmAdminPassword string

@description('Active Directory domain name')
param domainName string = 'contoso.local'

@description('Active Directory NetBIOS name')
param domainNetBiosName string = 'CONTOSO'

@description('Deploy domain controller VM')
param deployDomainController bool = true

@description('Repository URL for bootstrap scripts')
param repositoryUrl string = 'https://raw.githubusercontent.com/broberts23/vsCode/main/project-functionapp-roles/scripts'

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
var vnetName = '${baseName}-vnet-${environment}-${uniqueSuffix}'
var dcVmName = '${baseName}-dc-${environment}'
var dcNicName = '${dcVmName}-nic'
var dcPublicIpName = '${dcVmName}-pip'
var nsgName = '${baseName}-nsg-${environment}-${uniqueSuffix}'

// Conditional AD service account values
var effectiveAdServiceAccountUsername = deployDomainController
  ? '${domainNetBiosName}\\svc-functionapp'
  : adServiceAccountUsername
var effectiveAdServiceAccountPassword = deployDomainController ? serviceAccountPassword : adServiceAccountPassword

// ====================================
// Resources
// ====================================

// Log Analytics Workspace
// https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview
resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
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
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-06-01' = {
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
resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
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
resource adServiceAccountSecret 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: keyVault
  name: 'ENTRA-PWDRESET-RW'
  properties: {
    value: '{"username":"${effectiveAdServiceAccountUsername}","password":"${effectiveAdServiceAccountPassword}"}'
    contentType: 'application/json'
    attributes: {
      enabled: true
    }
  }
}

// Key Vault Secret for Domain Controller VM Admin Credentials (optional storage)
// Stores the VM administrator username and password used for the domain controller deployment
resource vmAdminSecret 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = if (deployDomainController) {
  parent: keyVault
  name: 'DC-VM-ADMIN-CREDENTIAL'
  properties: {
    value: '{"username":"${vmAdminUsername}","password":"${vmAdminPassword}"}'
    contentType: 'application/json'
    attributes: {
      enabled: true
    }
  }
}

// Network Security Group
// https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
resource nsg 'Microsoft.Network/networkSecurityGroups@2025-01-01' = if (deployDomainController) {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowRDP'
        properties: {
          priority: 1000
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
      {
        name: 'AllowADDS'
        properties: {
          priority: 1010
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [
            '389' // LDAP
            '636' // LDAPS
            '3268' // Global Catalog
            '3269' // Global Catalog SSL
            '88' // Kerberos
            '53' // DNS
            '445' // SMB
          ]
        }
      }
    ]
  }
}

// Virtual Network
// https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview
resource vnet 'Microsoft.Network/virtualNetworks@2025-01-01' = if (deployDomainController) {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'DomainControllerSubnet'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
      {
        name: 'FunctionAppSubnet'
        properties: {
          addressPrefix: '10.0.2.0/24'
          delegations: [
            {
              name: 'delegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms'
              }
            }
          ]
        }
      }
    ]
  }
}

// Public IP for Domain Controller
// https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses
resource dcPublicIp 'Microsoft.Network/publicIPAddresses@2025-01-01' = if (deployDomainController) {
  name: dcPublicIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: toLower(dcVmName)
    }
  }
}

// Network Interface for Domain Controller
// https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface
resource dcNic 'Microsoft.Network/networkInterfaces@2025-01-01' = if (deployDomainController) {
  name: dcNicName
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: '10.0.1.4'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, 'DomainControllerSubnet')
          }
          publicIPAddress: {
            id: dcPublicIp.id
          }
        }
      }
    ]
  }
  dependsOn: [
    vnet
  ]
}

// Domain Controller Virtual Machine
// https://learn.microsoft.com/azure/virtual-machines/windows/overview
resource dcVm 'Microsoft.Compute/virtualMachines@2025-04-01' = if (deployDomainController) {
  name: dcVmName
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: take(dcVmName, 15)
      adminUsername: vmAdminUsername
      adminPassword: vmAdminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
        timeZone: 'UTC'
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter'
        version: 'latest'
      }
      osDisk: {
        name: '${dcVmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
      dataDisks: [
        {
          name: '${dcVmName}-datadisk'
          diskSizeGB: 32
          lun: 0
          createOption: 'Empty'
          managedDisk: {
            storageAccountType: 'Premium_LRS'
          }
        }
      ]
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: dcNic.id
          properties: {
            primary: true
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        storageUri: storageAccount.properties.primaryEndpoints.blob
      }
    }
  }
}

// Custom Script Extension to bootstrap AD DS
// https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-windows
resource dcBootstrap 'Microsoft.Compute/virtualMachines/extensions@2025-04-01' = if (deployDomainController) {
  parent: dcVm
  name: 'BootstrapADDS'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    protectedSettings: {
      fileUris: [
        '${repositoryUrl}/Bootstrap-ADDSDomain.ps1'
      ]
      commandToExecute: 'powershell.exe -ExecutionPolicy Bypass -File Bootstrap-ADDSDomain.ps1 -DomainName "${domainName}" -DomainNetBiosName "${domainNetBiosName}" -SafeModeAdminPassword "${vmAdminPassword}"'
    }
  }
}

// App Service Plan (Linux Consumption)
// https://learn.microsoft.com/azure/app-service/overview-hosting-plans
resource appServicePlan 'Microsoft.Web/serverfarms@2025-03-01' = {
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
resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
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

// App Service Authentication / Authorization (Easy Auth)
// https://learn.microsoft.com/azure/app-service/configure-authentication-provider-aad
resource functionAppAuth 'Microsoft.Web/sites/config@2025-03-01' = {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: 'https://sts.windows.net/${tenantId}/v2.0'
          clientId: clientId
        }
        validation: {
          allowedAudiences: [
            'api://${clientId}'
          ]
        }
      }
    }
    login: {
      tokenStore: {
        enabled: true
      }
    }
    platform: {
      enabled: true
    }
  }
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
