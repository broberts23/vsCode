// Module: Azure Container Apps job for GitHub self-hosted runners
// References:
// - Jobs resource: https://learn.microsoft.com/azure/container-apps/jobs
// - GitHub runner scaler: https://keda.sh/docs/latest/scalers/github-runner/

param name string
param location string
param environmentId string
param image string
@description('Container CPU in cores (supports values such as 0.5, 1.0, 2.0).')
param containerCpu string = '2.0'
param containerMemory string = '4Gi'
param containerEnv array = [] // Array of objects { name: string, value?: string, secretRef?: string }
param jobSecrets array = [] // Array of objects { name: string, value?: string, keyVaultUrl?: string, identity?: string }
param registries array = [] // Array of registry credentials { server: string, identity?: string, passwordSecretRef?: string }

@description('Enable system-assigned managed identity for the job.')
param systemAssigned bool = true
@description('Optional single user-assigned managed identity resource ID to associate with the job.')
param userAssignedIdentityId string = ''

@description('Parallelism determines how many replicas run per execution.')
param parallelism int = 1
@description('Number of replicas required to report success before the job execution is marked successful.')
param replicaCompletionCount int = 1
@description('Maximum retry count for failed replicas.')
param replicaRetryLimit int = 0
@description('Maximum execution time in seconds per replica.')
param replicaTimeout int = 1800

@description('Minimum executions triggered per polling interval.')
param minExecutions int = 0
@description('Maximum executions triggered per polling interval.')
param maxExecutions int = 10
@description('KEDA polling interval in seconds.')
param pollingInterval int = 30

@description('Scale rule metadata such as owner, repos, runnerScope, labels, githubAPIURL, targetWorkflowQueueLength.')
param scaleRuleMetadata object

@description('Scale rule secret auth configuration such as personalAccessToken=secretref:personal-access-token.')
param scaleRuleAuth array = [] // Array of objects { triggerParameter: string, secretRef: string }

@description('Optional environment variables to override command arguments.')
param command array = []
param args array = []

var identityType = systemAssigned
  ? (empty(userAssignedIdentityId) ? 'SystemAssigned' : 'SystemAssigned,UserAssigned')
  : (empty(userAssignedIdentityId) ? 'None' : 'UserAssigned')

resource githubRunnerJob 'Microsoft.App/jobs@2025-01-01' = {
  name: name
  location: location
  identity: {
    type: identityType
    userAssignedIdentities: empty(userAssignedIdentityId)
      ? {}
      : {
          '${userAssignedIdentityId}': {}
        }
  }
  properties: {
    environmentId: environmentId
    configuration: {
      triggerType: 'Event'
      replicaRetryLimit: replicaRetryLimit
      replicaTimeout: replicaTimeout
      secrets: jobSecrets
      registries: registries
      eventTriggerConfig: {
        parallelism: parallelism
        replicaCompletionCount: replicaCompletionCount
        scale: {
          minExecutions: minExecutions
          maxExecutions: maxExecutions
          pollingInterval: pollingInterval
          rules: [
            {
              name: 'github-runner'
              type: 'github-runner'
              metadata: scaleRuleMetadata
              auth: scaleRuleAuth
            }
          ]
        }
      }
    }
    template: {
      containers: [
        {
          name: 'runner'
          image: image
          env: containerEnv
          command: command
          args: args
          resources: {
            cpu: json(containerCpu)
            memory: containerMemory
          }
        }
      ]
    }
  }
}

output jobId string = githubRunnerJob.id
output principalId string = githubRunnerJob.identity.principalId
