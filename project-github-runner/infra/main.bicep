// Main deployment template for project-github-runner
// Composes Log Analytics, Container Apps environment, optional ACR, and the GitHub runner job.

targetScope = 'resourceGroup'

@description('Azure region for all resources.')
param location string

@description('Project-friendly base name used for resource naming.')
param baseName string = 'gh-runner'

@description('Tags applied to all resources.')
param tags object = {}

@description('Retention in days for Log Analytics workspace.')
param logAnalyticsRetentionInDays int = 30

@description('Name for Container Apps managed environment.')
param containerAppEnvironmentName string = '${baseName}-env'

@description('Optional workload profile type name (e.g., Consumption, D4). Leave empty to use default serverless profile.')
param workloadProfileName string = ''

@description('Fully qualified container image path (e.g., myacr.azurecr.io/github-actions-runner:1.0).')
param containerImage string

@description('Container CPU cores (expressed as string to support decimal values).')
param containerCpu string = '2.0'

@description('Container memory allocation (e.g., 4Gi).')
param containerMemory string = '4Gi'

@description('Job runner labels (comma-separated string).')
param runnerLabels string = 'self-hosted,azure-container-apps'

@description('GitHub repository owner (organization or user).')
param githubOwner string

@description('GitHub repository name.')
param githubRepo string

@description('Secret name used to store GitHub PAT (resolved via Container Apps secrets).')
param githubPatSecretName string = 'personal-access-token'

@description('Secret value for GitHub PAT. Provide via secure parameter or reference to Key Vault in production.')
@secure()
param githubPatSecretValue string

@description('Optional additional environment variables passed to the runner container.')
param additionalEnv array = []

@description('Minimum job executions triggered per polling interval.')
param minExecutions int = 0

@description('Maximum job executions triggered per polling interval.')
param maxExecutions int = 10

@description('Polling interval (seconds) for the GitHub runner KEDA scaler.')
param pollingInterval int = 30

@description('Target workflow queue length before scaling additional executions.')
param targetWorkflowQueueLength int = 1

@description('Optional user-assigned managed identity resource ID for the job and registry access.')
param userAssignedIdentityId string = ''

@description('Set to true to deploy a new Azure Container Registry; set false to reuse an existing registry.')
param deployContainerRegistry bool = true

@description('Existing ACR login server (required if deployContainerRegistry is false).')
param existingAcrLoginServer string = ''

@description('Existing ACR resource ID (required if deployContainerRegistry is false).')
param existingAcrResourceId string = ''

@description('When deploying a new ACR, specify the name (must be globally unique).')
param acrName string = '${baseName}acr'

@description('SKU for new ACR (Basic, Standard, Premium).')
param acrSku string = 'Basic'

var locationNormalized = toLower(replace(location, ' ', ''))
var workspaceName = '${baseName}-${locationNormalized}-law'
var logAnalyticsResourceId = resourceId('Microsoft.OperationalInsights/workspaces', workspaceName)

module works 'containerapps/logAnalytics.bicep' = {
  name: '${baseName}-log'
  params: {
    name: workspaceName
    location: location
    retentionInDays: logAnalyticsRetentionInDays
    tags: tags
  }
}

var logAnalyticsSharedKey = listKeys(logAnalyticsResourceId, '2023-09-01').primarySharedKey

module env 'containerapps/managedEnvironment.bicep' = {
  name: '${baseName}-env'
  params: {
    name: containerAppEnvironmentName
    location: location
    logAnalyticsCustomerId: works.outputs.customerId
    logAnalyticsSharedKey: logAnalyticsSharedKey
    tags: tags
    workloadProfileName: workloadProfileName
  }
}

module acr 'containerapps/containerRegistry.bicep' = if (deployContainerRegistry) {
  name: '${baseName}-acr'
  params: {
    name: acrName
    location: location
    sku: acrSku
    tags: tags
    principalId: empty(userAssignedIdentityId)
      ? ''
      : reference(userAssignedIdentityId, '2018-11-30', 'Full').principalId
    principalType: 'ServicePrincipal'
  }
}

var newAcrLoginServer = '${toLower(acrName)}.azurecr.io'
var newAcrResourceId = resourceId('Microsoft.ContainerRegistry/registries', acrName)

var registryLoginServer = deployContainerRegistry ? newAcrLoginServer : existingAcrLoginServer
var registryResourceId = deployContainerRegistry ? newAcrResourceId : existingAcrResourceId

var baseRunnerEnv = [
  {
    name: 'GH_URL'
    value: 'https://github.com/${githubOwner}/${githubRepo}'
  }
  {
    name: 'REGISTRATION_TOKEN_API_URL'
    value: 'https://api.github.com/repos/${githubOwner}/${githubRepo}/actions/runners/registration-token'
  }
  {
    name: 'RUNNER_LABELS'
    value: runnerLabels
  }
  {
    name: 'GITHUB_PAT'
    secretRef: githubPatSecretName
  }
]

var runnerEnv = concat(baseRunnerEnv, additionalEnv)

module job 'containerapps/githubRunnerJob.bicep' = {
  name: '${baseName}-job'
  params: {
    name: '${baseName}-job'
    location: location
    environmentId: env.outputs.environmentId
    image: containerImage
    containerCpu: containerCpu
    containerMemory: containerMemory
    containerEnv: runnerEnv
    jobSecrets: [
      {
        name: githubPatSecretName
        value: githubPatSecretValue
      }
    ]
    registries: empty(registryLoginServer)
      ? []
      : [
          {
            server: registryLoginServer
            identity: empty(userAssignedIdentityId) ? 'system' : userAssignedIdentityId
          }
        ]
    systemAssigned: true
    userAssignedIdentityId: userAssignedIdentityId
    parallelism: 1
    replicaCompletionCount: 1
    replicaRetryLimit: 0
    replicaTimeout: 1800
    minExecutions: minExecutions
    maxExecutions: maxExecutions
    pollingInterval: pollingInterval
    scaleRuleMetadata: {
      githubAPIURL: 'https://api.github.com'
      owner: githubOwner
      repos: githubRepo
      runnerScope: 'repo'
      labels: runnerLabels
      targetWorkflowQueueLength: string(targetWorkflowQueueLength)
    }
    scaleRuleAuth: [
      {
        triggerParameter: 'personalAccessToken'
        secretRef: githubPatSecretName
      }
    ]
  }
}

output containerAppsEnvironmentId string = env.outputs.environmentId
output containerAppsJobId string = job.outputs.jobId
output logAnalyticsWorkspaceId string = works.outputs.workspaceId
output containerRegistryId string = registryResourceId
output containerRegistryLoginServer string = registryLoginServer
