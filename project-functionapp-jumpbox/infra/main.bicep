targetScope = 'resourceGroup'

@description('Environment name')
@allowed(['dev', 'test', 'prod'])
param environment string = 'dev'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Base name for all resources')
param baseName string = 'legacyjump'

@description('Tags applied to resources')
param tags object = {
  Environment: environment
  Application: 'LegacyPowerShellJumpbox'
  ManagedBy: 'Bicep'
}

@description('Entra tenant ID used by Easy Auth')
param tenantId string

@description('Application ID for the protected API')
param clientId string

@description('Required app role claim enforced by the function')
param requiredRole string = 'Role.LegacyCommand.Invoke'

@description('Windows administrator username for both VMs')
param vmAdminUsername string = 'azureadmin'

@description('Windows administrator password for both VMs')
@secure()
param vmAdminPassword string

@description('Password for the remoting service account stored in Key Vault')
@secure()
param serviceAccountPassword string

@description('Optional object ID of the deployment principal that should receive Key Vault Administrator on the vault')
param deploymentPrincipalObjectId string = ''

@description('Principal type for the deployment principal role assignment')
@allowed([
  'User'
  'ServicePrincipal'
  'Group'
])
param deploymentPrincipalType string = 'User'

@description('Active Directory domain name')
param domainName string = 'contoso.local'

@description('Active Directory NetBIOS name')
param domainNetBiosName string = 'CONTOSO'

var uniqueSuffix = uniqueString(resourceGroup().id, baseName)
var compactBaseName = toLower(replace(baseName, '-', ''))
var storagePrefix = take(compactBaseName, 10)
var keyVaultPrefix = take(compactBaseName, 8)
var functionAppName = '${baseName}-func-${environment}-${uniqueSuffix}'
var appServicePlanName = '${baseName}-asp-${environment}-${uniqueSuffix}'
var storageAccountName = toLower('${storagePrefix}st${environment}${take(uniqueSuffix, 8)}')
var keyVaultName = toLower('${keyVaultPrefix}kv${environment}${take(uniqueSuffix, 8)}')
var logAnalyticsName = '${baseName}-log-${environment}-${uniqueSuffix}'
var appInsightsName = '${baseName}-ai-${environment}-${uniqueSuffix}'
var vnetName = '${baseName}-vnet-${environment}-${uniqueSuffix}'
var nsgName = '${baseName}-nsg-${environment}-${uniqueSuffix}'
var dcVmName = '${baseName}-dc-${environment}'
var managementVmName = '${baseName}-mgmt-${environment}'
var dcNicName = '${dcVmName}-nic'
var managementNicName = '${managementVmName}-nic'
var dcPublicIpName = '${dcVmName}-pip'
var managementPublicIpName = '${managementVmName}-pip'
var managementHostFqdn = '${managementVmName}.${domainName}'
var remotingServiceUsername = '${domainNetBiosName}\\svc-legacyjump'

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

resource storageAccount 'Microsoft.Storage/storageAccounts@2025-08-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
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
    enableSoftDelete: false
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource remotingCredentialSecret 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: keyVault
  name: 'LEGACY-JUMPBOX-CREDENTIAL'
  properties: {
    value: '{"username":"${remotingServiceUsername}","password":"${serviceAccountPassword}"}'
    contentType: 'application/json'
    attributes: {
      enabled: true
    }
  }
}

resource vmAdminSecret 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = {
  parent: keyVault
  name: 'JUMPBOX-VM-ADMIN-CREDENTIAL'
  properties: {
    value: '{"username":"${vmAdminUsername}","password":"${vmAdminPassword}"}'
    contentType: 'application/json'
    attributes: {
      enabled: true
    }
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowRdp'
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
        name: 'AllowAddsWithinVnet'
        properties: {
          priority: 1010
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'VirtualNetwork'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRanges: [
            '53'
            '88'
            '135'
            '389'
            '445'
            '636'
            '3268'
            '3269'
          ]
        }
      }
      {
        name: 'AllowWinRmHttpsFromFunctionSubnet'
        properties: {
          priority: 1020
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.3.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '5986'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
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
        name: 'ManagementSubnet'
        properties: {
          addressPrefix: '10.0.2.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
      {
        name: 'FunctionAppSubnet'
        properties: {
          addressPrefix: '10.0.3.0/24'
          delegations: [
            {
              name: 'functionDelegation'
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

resource dcPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: dcPublicIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: toLower('${dcVmName}${take(uniqueSuffix, 5)}')
    }
  }
}

resource managementPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: managementPublicIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: toLower('${managementVmName}${take(uniqueSuffix, 5)}')
    }
  }
}

resource dcNic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
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
}

resource managementNic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: managementNicName
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Static'
          privateIPAddress: '10.0.2.4'
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, 'ManagementSubnet')
          }
          publicIPAddress: {
            id: managementPublicIp.id
          }
        }
      }
    ]
  }
}

resource dcVm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: dcVmName
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2ads_v6'
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
        sku: '2022-datacenter-g2'
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

resource managementVm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: managementVmName
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2ads_v6'
    }
    priority: 'Spot'
    evictionPolicy: 'Deallocate'
    billingProfile: {
      maxPrice: -1
    }
    osProfile: {
      computerName: take(managementVmName, 15)
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
        sku: '2022-datacenter-g2'
        version: 'latest'
      }
      osDisk: {
        name: '${managementVmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: managementNic.id
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

resource appServicePlan 'Microsoft.Web/serverfarms@2025-03-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  sku: {
    name: 'EP1'
    tier: 'ElasticPremium'
  }
  kind: 'functionapp'
  properties: {
    reserved: false
  }
}

resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    reserved: false
    httpsOnly: true
    clientAffinityEnabled: false
    virtualNetworkSubnetId: resourceId('Microsoft.Network/virtualNetworks/subnets', vnetName, 'FunctionAppSubnet')
    siteConfig: {
      powerShellVersion: '7.4'
      use32BitWorkerProcess: false
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      functionAppScaleLimit: 200
      minimumElasticInstanceCount: 1
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
          name: 'MANAGEMENT_CREDENTIAL_JSON'
          value: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/LEGACY-JUMPBOX-CREDENTIAL/)'
        }
        {
          name: 'MANAGEMENT_HOST_FQDN'
          value: managementHostFqdn
        }
        {
          name: 'MANAGEMENT_HOST_PORT'
          value: '5986'
        }
        {
          name: 'WINRM_CERTIFICATE_BASE64'
          value: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/JUMPBOX-WINRM-CERT-CER/)'
        }
        {
          name: 'DOMAIN_NAME'
          value: domainName
        }
        {
          name: 'WEBSITE_DNS_SERVER'
          value: '10.0.1.4'
        }
        {
          name: 'WEBSITE_VNET_ROUTE_ALL'
          value: '1'
        }
      ]
    }
  }
  dependsOn: [
    remotingCredentialSecret
  ]
}

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
          openIdIssuer: '${az.environment().authentication.loginEndpoint}${tenantId}/v2.0'
          clientId: clientId
        }
        validation: {
          allowedAudiences: [
            clientId
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

resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '4633458b-17de-408a-b874-0445c86b69e6'
    )
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource deploymentPrincipalKeyVaultAdminRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(deploymentPrincipalObjectId)) {
  name: guid(keyVault.id, deploymentPrincipalObjectId, 'Key Vault Administrator')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '00482a5a-887f-4fb3-b363-3b7fe8e74483'
    )
    principalId: deploymentPrincipalObjectId
    principalType: deploymentPrincipalType
  }
}

output functionAppName string = functionApp.name
output functionAppHostName string = functionApp.properties.defaultHostName
output functionAppPrincipalId string = functionApp.identity.principalId
output keyVaultName string = keyVault.name
output keyVaultUri string = keyVault.properties.vaultUri
output domainControllerVmName string = dcVm.name
output domainControllerFqdn string = '${dcVmName}.${domainName}'
output managementVmName string = managementVm.name
output managementVmFqdn string = managementHostFqdn
output managementVmPrivateIp string = '10.0.2.4'
output domainName string = domainName
