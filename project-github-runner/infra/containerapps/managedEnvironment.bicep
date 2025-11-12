// Module: Azure Container Apps managed environment
// Reference: https://learn.microsoft.com/azure/container-apps/environment

param name string
param location string
param logAnalyticsCustomerId string
@secure()
param logAnalyticsSharedKey string
param tags object = {}
param workloadProfileName string = ''

resource managedEnvironment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalyticsCustomerId
        sharedKey: logAnalyticsSharedKey
      }
    }
    workloadProfiles: empty(workloadProfileName)
      ? []
      : [
          {
            name: workloadProfileName
            workloadProfileType: 'D4'
          }
        ]
  }
}

output environmentId string = managedEnvironment.id
