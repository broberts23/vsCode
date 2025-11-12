// Module: Log Analytics workspace for Azure Container Apps
// Reference: https://learn.microsoft.com/azure/azure-monitor/logs/quick-create-workspace

param name string
param location string
param retentionInDays int = 30
param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
  }
}

output customerId string = workspace.properties.customerId
output workspaceId string = workspace.id
