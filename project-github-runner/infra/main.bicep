// Main deployment template for project-github-runner
// Composes Log Analytics, Container Apps environment, ACR, and the GitHub runner job.

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

@description('Virtual network CIDR block for the Container Apps environment.')
param virtualNetworkAddressPrefix string = '10.10.0.0/16'

@description('Subnet CIDR dedicated to the Container Apps environment (min /27).')
param containerAppsSubnetPrefix string = '10.10.0.0/23'

@description('CIDR reserved for platform infrastructure IP addresses; must not overlap with the virtual network.')
param platformReservedCidr string = '10.200.0.0/24'

@description('DNS IP address from within the platform reserved CIDR range.')
param platformReservedDnsIp string = '10.200.0.10'

@description('CIDR range for the Docker bridge network used by the environment.')
param dockerBridgeCidr string = '172.16.0.0/16'

@description('Deploy the Container Apps environment as internal only when true (no public ingress).')
param internalEnvironment bool = false

@description('Enable workload-profile features for the Container Apps environment. When true, platform-reserved CIDR settings are ignored per ACA networking rules.')
param enableWorkloadProfiles bool = true

@description('Workload profile definitions for the Container Apps environment. Leave empty to default to the required Consumption profile when integrating with a delegated subnet.')
param workloadProfiles array = []

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

@description('Secret value for GitHub PAT. Leave empty when using GitHub App authentication.')
@secure()
param githubPatSecretValue string = ''

@description('Secret name used to expose the GitHub App private key to the runner job when using GitHub App authentication.')
param githubAppKeySecretName string = 'github-app-key'

@description('GitHub App private key in PEM format. Provide when using GitHub App authentication; leave empty to fall back to PAT.')
@secure()
param githubAppPrivateKey string = ''

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

@description('When deploying a new ACR, specify the name (must be globally unique).')
param acrName string = '${baseName}acr'

@description('SKU for new ACR (Basic, Standard, Premium).')
param acrSku string = 'Basic'

@description('GitHub API endpoint used by the scaler; override for GitHub Enterprise.')
param githubApiUrl string = 'https://api.github.com'

@description('Base GitHub server URL for the runner to register against.')
param githubServerUrl string = 'https://github.com'

@description('Scope used by the GitHub runner scaler (repo, org, ent).')
@allowed([
  'repo'
  'org'
  'ent'
])
param githubRunnerScope string = 'repo'

@description('Override the comma-delimited repository list monitored by the scaler. Defaults to githubRepo when the scope is repo.')
param githubRunnerRepositories string = ''

@description('Disable default runner labels (self-hosted, linux, x64) when true.')
param disableDefaultRunnerLabels bool = false

@description('Match unlabeled GitHub jobs with unlabeled runners when true.')
param matchUnlabeledRunnerJobs bool = false

@description('Enable GitHub API etag support to reduce rate limit usage when true.')
param enableGithubEtags bool = false

@description('Optional GitHub App application ID for scaler authentication.')
param githubAppApplicationId string = ''

@description('Optional GitHub App installation ID for scaler authentication.')
param githubAppInstallationId string = ''

@description('Additional KEDA scale rule auth entries (array of objects with triggerParameter and secretRef).')
param additionalScaleRuleAuth array = []

var locationNormalized = toLower(replace(location, ' ', ''))
var workspaceName = '${baseName}-${locationNormalized}-law'
var logAnalyticsResourceId = resourceId('Microsoft.OperationalInsights/workspaces', workspaceName)
var githubApiUrlNormalized = endsWith(githubApiUrl, '/')
  ? substring(githubApiUrl, 0, max(length(githubApiUrl) - 1, 0))
  : githubApiUrl
var githubServerUrlNormalized = endsWith(githubServerUrl, '/')
  ? substring(githubServerUrl, 0, max(length(githubServerUrl) - 1, 0))
  : githubServerUrl
var githubRunnerUrl = githubRunnerScope == 'org'
  ? '${githubServerUrlNormalized}/${githubOwner}'
  : (githubRunnerScope == 'ent'
      ? '${githubServerUrlNormalized}/enterprises/${githubOwner}'
      : '${githubServerUrlNormalized}/${githubOwner}/${githubRepo}')
var githubRegistrationTokenApiUrl = githubRunnerScope == 'org'
  ? '${githubApiUrlNormalized}/orgs/${githubOwner}/actions/runners/registration-token'
  : (githubRunnerScope == 'ent'
      ? '${githubApiUrlNormalized}/enterprises/${githubOwner}/actions/runners/registration-token'
      : '${githubApiUrlNormalized}/repos/${githubOwner}/${githubRepo}/actions/runners/registration-token')
var githubScaleRepositories = empty(githubRunnerRepositories)
  ? (githubRunnerScope == 'repo' ? githubRepo : '')
  : githubRunnerRepositories
var useGithubAppAuth = !empty(githubAppApplicationId) && !empty(githubAppInstallationId) && !empty(githubAppPrivateKey)
var usePatAuth = !empty(githubPatSecretValue)
var createRunnerIdentity = empty(userAssignedIdentityId)
var runnerIdentityName = '${baseName}-job-mi'

resource runnerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2024-11-30' = if (createRunnerIdentity) {
  name: runnerIdentityName
  location: location
  tags: tags
}

var effectiveUserAssignedIdentityId = createRunnerIdentity ? runnerIdentity.id : userAssignedIdentityId
var userAssignedPrincipalId = createRunnerIdentity
  ? reference(runnerIdentity.id, '2024-11-30', 'Full').principalId
  : (empty(userAssignedIdentityId) ? '' : reference(userAssignedIdentityId, '2024-11-30', 'Full').principalId)
var sanitizedBaseName = replace(toLower(baseName), '-', '')
var keyVaultUniqueSuffix = substring(uniqueString(resourceGroup().id, baseName), 0, 13)
var generatedKeyVaultName = take('kv${sanitizedBaseName}${keyVaultUniqueSuffix}', 24)

module network 'network/vnet.bicep' = {
  name: '${baseName}-network'
  params: {
    name: '${baseName}-vnet'
    location: location
    addressPrefix: virtualNetworkAddressPrefix
    subnetName: '${baseName}-ca-subnet'
    subnetPrefix: containerAppsSubnetPrefix
    nsgName: '${baseName}-nsg'
    tags: tags
  }
}

module works 'containerapps/logAnalytics.bicep' = {
  name: '${baseName}-log'
  params: {
    name: workspaceName
    location: location
    retentionInDays: logAnalyticsRetentionInDays
    tags: tags
  }
}

var logAnalyticsSharedKey = listKeys(logAnalyticsResourceId, '2025-02-01').primarySharedKey

module env 'containerapps/managedEnvironment.bicep' = {
  name: '${baseName}-env'
  params: {
    name: containerAppEnvironmentName
    location: location
    logAnalyticsCustomerId: works.outputs.customerId
    logAnalyticsSharedKey: logAnalyticsSharedKey
    tags: tags
    enableWorkloadProfiles: enableWorkloadProfiles
    workloadProfiles: workloadProfiles
    infrastructureSubnetId: network.outputs.subnetId
    platformReservedCidr: platformReservedCidr
    platformReservedDnsIp: platformReservedDnsIp
    dockerBridgeCidr: dockerBridgeCidr
    internalEnvironment: internalEnvironment
  }
}

module acr 'containerapps/containerRegistry.bicep' = {
  name: '${baseName}-acr'
  params: {
    name: acrName
    location: location
    sku: acrSku
    tags: tags
  }
}

resource acrResource 'Microsoft.ContainerRegistry/registries@2025-04-01' existing = {
  name: acrName
  dependsOn: [
    acr
  ]
}

module keyVault 'secrets/keyVault.bicep' = if (useGithubAppAuth) {
  name: '${baseName}-kv'
  params: {
    name: generatedKeyVaultName
    location: location
    tags: tags
  }
}

module githubAppKeySecret 'secrets/keyVaultSecret.bicep' = if (useGithubAppAuth) {
  name: '${baseName}-github-app-key'
  params: {
    vaultName: generatedKeyVaultName
    secretName: githubAppKeySecretName
    secretValue: githubAppPrivateKey
    tags: tags
  }
}

resource keyVaultResource 'Microsoft.KeyVault/vaults@2025-05-01' existing = if (useGithubAppAuth) {
  name: generatedKeyVaultName
}

var githubAppKeySecretUri = useGithubAppAuth
  ? reference(
      resourceId('Microsoft.KeyVault/vaults/secrets', generatedKeyVaultName, githubAppKeySecretName),
      '2025-05-01',
      'Full'
    ).properties.secretUri
  : ''

var registryLoginServer = acr.outputs.loginServer
var registryResourceId = acr.outputs.registryId

var scaleSecretName = useGithubAppAuth ? githubAppKeySecretName : (usePatAuth ? githubPatSecretName : '')
var scaleAuthTriggerParameter = useGithubAppAuth ? 'appKey' : 'personalAccessToken'

var baseRunnerEnv = [
  {
    name: 'GH_URL'
    value: githubRunnerUrl
  }
  {
    name: 'GITHUB_API_URL'
    value: githubApiUrlNormalized
  }
  {
    name: 'REGISTRATION_TOKEN_API_URL'
    value: githubRegistrationTokenApiUrl
  }
  {
    name: 'RUNNER_LABELS'
    value: runnerLabels
  }
]

var runnerAuthEnv = useGithubAppAuth
  ? [
      {
        name: 'APP_ID'
        value: githubAppApplicationId
      }
      {
        name: 'APP_INSTALLATION_ID'
        value: githubAppInstallationId
      }
      {
        name: 'APP_PRIVATE_KEY'
        secretRef: githubAppKeySecretName
      }
    ]
  : (usePatAuth
      ? [
          {
            name: 'GITHUB_PAT'
            secretRef: githubPatSecretName
          }
        ]
      : [])

var runnerEnv = concat(baseRunnerEnv, runnerAuthEnv, additionalEnv)

var jobSecretIdentity = empty(userAssignedIdentityId) ? 'system' : effectiveUserAssignedIdentityId

var jobSecrets = useGithubAppAuth
  ? [
      {
        name: githubAppKeySecretName
        keyVaultUrl: githubAppKeySecretUri
        identity: jobSecretIdentity
      }
    ]
  : (usePatAuth
      ? [
          {
            name: githubPatSecretName
            value: githubPatSecretValue
          }
        ]
      : [])

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
    jobSecrets: jobSecrets
    registries: [
      {
        server: registryLoginServer
        identity: empty(effectiveUserAssignedIdentityId) ? 'system' : effectiveUserAssignedIdentityId
      }
    ]
    systemAssigned: true
    userAssignedIdentityId: effectiveUserAssignedIdentityId
    parallelism: 1
    replicaCompletionCount: 1
    replicaRetryLimit: 0
    replicaTimeout: 1800
    minExecutions: minExecutions
    maxExecutions: maxExecutions
    pollingInterval: pollingInterval
    githubOwner: githubOwner
    githubApiUrl: githubApiUrlNormalized
    runnerScope: githubRunnerScope
    githubRepositories: githubScaleRepositories
    scaleRunnerLabels: runnerLabels
    noDefaultLabels: disableDefaultRunnerLabels
    matchUnlabeledJobsWithUnlabeledRunners: matchUnlabeledRunnerJobs
    enableEtags: enableGithubEtags
    applicationId: useGithubAppAuth ? githubAppApplicationId : ''
    installationId: useGithubAppAuth ? githubAppInstallationId : ''
    targetWorkflowQueueLength: targetWorkflowQueueLength
    scaleSecretName: scaleSecretName
    scaleAuthTriggerParameter: scaleAuthTriggerParameter
    additionalScaleRuleAuth: additionalScaleRuleAuth
  }
}

var acrPullRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)
var keyVaultSecretsUserRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)

resource runnerIdentityAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(effectiveUserAssignedIdentityId)) {
  name: guid(acrName, '${baseName}-runner-mi', 'acrPull')
  scope: acrResource
  dependsOn: [
    acr
  ]
  properties: {
    roleDefinitionId: acrPullRoleDefinitionId
    principalId: userAssignedPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource jobAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acrName, '${baseName}-job', 'acrPull')
  scope: acrResource
  properties: {
    roleDefinitionId: acrPullRoleDefinitionId
    principalId: job.outputs.principalId
    principalType: 'ServicePrincipal'
  }
}

resource jobKeyVaultSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (useGithubAppAuth) {
  name: guid(keyVaultResource.id, '${baseName}-job', 'kvSecretsUser')
  scope: keyVaultResource
  dependsOn: [
    keyVault
  ]
  properties: {
    roleDefinitionId: keyVaultSecretsUserRoleDefinitionId
    principalId: job.outputs.principalId
    principalType: 'ServicePrincipal'
  }
}

output containerAppsEnvironmentId string = env.outputs.environmentId
output containerAppsJobId string = job.outputs.jobId
output jobPrincipalId string = job.outputs.principalId
output logAnalyticsWorkspaceId string = works.outputs.workspaceId
output containerRegistryId string = registryResourceId
output containerRegistryLoginServer string = registryLoginServer
output virtualNetworkId string = network.outputs.virtualNetworkId
output containerAppsSubnetId string = network.outputs.subnetId
output networkSecurityGroupId string = network.outputs.networkSecurityGroupId
output keyVaultName string = useGithubAppAuth ? generatedKeyVaultName : ''
output githubAppKeySecretUri string = useGithubAppAuth ? githubAppKeySecretUri : ''
