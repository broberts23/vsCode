// Module: Virtual network, subnet, and network security group for Azure Container Apps
// References:
// - Virtual network configuration: https://learn.microsoft.com/azure/container-apps/custom-virtual-networks

param name string
param location string
param addressPrefix string
param subnetName string = 'containerapps-infra'
param subnetPrefix string
param nsgName string = '${name}-nsg'
param tags object = {}

@description('Additional security rules to append to the NSG. Each rule should follow the Microsoft.Network/networkSecurityGroups securityRules schema.')
param securityRules array = []

resource networkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: securityRules
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetPrefix
          delegations: [
            {
              name: 'containerAppsDelegation'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
          networkSecurityGroup: {
            id: networkSecurityGroup.id
          }
        }
      }
    ]
  }
}

output virtualNetworkId string = virtualNetwork.id
output subnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', name, subnetName)
output networkSecurityGroupId string = networkSecurityGroup.id
