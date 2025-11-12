@description('Location for all resources')
param location string = resourceGroup().location

@description('Name of the container group to create')
param containerGroupName string = 'gh-runner-cg'

@description('Container image to run for the self-hosted runner')
param containerImage string = 'ghcr.io/actions/runner:latest'

@description('CPU cores for the container')
param cpuCores int = 1

@description('Memory in GB for the container')
param memoryInGb int = 2

@description('Environment variables for the container (array of {name, value})')
param containerEnv array = [
  {
    name: 'RUNNER_NAME'
    value: 'gha-runner'
  }
  {
    name: 'RUNNER_LABELS'
    value: 'self-hosted,azure'
  }
]

resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2025-09-01' = {
  name: containerGroupName
  location: location
  properties: {
    osType: 'Linux'
    containers: [
      {
        name: 'runner'
        properties: {
          image: containerImage
          resources: {
            requests: {
              cpu: cpuCores
              memoryInGB: memoryInGb
            }
          }
          environmentVariables: containerEnv
        }
      }
    ]
    restartPolicy: 'OnFailure'
  }
  identity: {
    type: 'SystemAssigned'
  }
}

output containerGroupId string = containerGroup.id
output containerGroupIdentityPrincipalId string = containerGroup.identity.principalId
output containerGroupIdentityTenantId string = containerGroup.identity.tenantId
