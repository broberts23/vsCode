targetScope = 'resourceGroup'

@description('Azure region for the partner configuration resource.')
param location string = resourceGroup().location

@description('Name of the partner configuration resource. Many deployments use `default`.')
param partnerConfigurationName string = 'default'

@description('The immutable ID of the partner registration to authorize. Leave empty to manage authorizations out-of-band.')
param authorizedPartnerRegistrationImmutableId string = ''

@description('Partner name to authorize in Event Grid Partner Configuration. Defaults to Microsoft Graph API.')
param authorizedPartnerName string = 'Microsoft Graph API'

@description('Expiration time (UTC) for the partner authorization entry. Defaults to 7 days from deployment time.')
param authorizedPartnerAuthorizationExpirationTimeInUtc string = dateTimeAdd(utcNow(), 'P7D')

@description('Partner topic name used by Microsoft Graph (created as part of subscription creation). If empty, Graph bootstrap and partner topic event subscription creation are skipped.')
param partnerTopicName string = ''

@description('Name of a user-assigned managed identity (in this resource group) used to run deploymentScripts and to own the Graph subscription. If empty, Graph bootstrap is skipped.')
param bootstrapUserAssignedIdentityName string = ''

var bootstrapIdentityResourceId = !empty(bootstrapUserAssignedIdentityName)
  ? resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', bootstrapUserAssignedIdentityName)
  : ''

var bootstrapIdentityClientId = !empty(bootstrapUserAssignedIdentityName)
  ? reference(bootstrapIdentityResourceId, '2025-01-31-preview').clientId
  : ''

var bootstrapIdentityPrincipalId = !empty(bootstrapUserAssignedIdentityName)
  ? reference(bootstrapIdentityResourceId, '2025-01-31-preview').principalId
  : ''

@description('Event subscription name (only used if `partnerTopicName` is set).')
param partnerTopicEventSubscriptionName string = 'to-governance-function'

@description('ResourceId of the Azure Function to invoke (only used if `partnerTopicName` is set). Example: /subscriptions/.../resourceGroups/.../providers/Microsoft.Web/sites/<app>/functions/<functionName>')
param functionResourceId string = ''

@description('Name of the Windows Function App (Microsoft.Web/sites).')
param functionAppName string = 'func-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Name of the Consumption plan (Microsoft.Web/serverfarms).')
param appServicePlanName string = 'plan-eg-governance-${uniqueString(resourceGroup().id)}'

@description('Name of the Storage Account used by the Function App. Must be globally unique and 3-24 lowercase alphanumeric.')
param storageAccountName string = toLower('st${uniqueString(resourceGroup().id)}')

@description('Name of the Azure Function within the Function App that Event Grid should invoke.')
param functionName string = 'GovernanceEventHandler'

@description('Name of the Azure Table Storage table used for idempotency/dedupe.')
param dedupeTableName string = 'DedupeKeys'

@description('Name of the Azure Storage Queue used as a cheap buffer for work items.')
param workQueueName string = 'governance-workitems'

@description('Name of the Azure Storage Queue used for Microsoft Graph subscription lifecycle maintenance work items.')
param lifecycleQueueName string = 'governance-lifecycle'

type PartnerAuthorizationEntry = {
  partnerRegistrationImmutableId: string
  partnerName: string
}

var shouldAuthorizePartner = !empty(authorizedPartnerRegistrationImmutableId) || !empty(authorizedPartnerName)

var authorizedPartnerEntry = union(
  !empty(authorizedPartnerRegistrationImmutableId)
    ? {
        partnerRegistrationImmutableId: authorizedPartnerRegistrationImmutableId
      }
    : {},
  !empty(authorizedPartnerName)
    ? {
        partnerName: authorizedPartnerName
      }
    : {},
  !empty(authorizedPartnerAuthorizationExpirationTimeInUtc)
    ? {
        authorizationExpirationTimeInUtc: authorizedPartnerAuthorizationExpirationTimeInUtc
      }
    : {}
)

resource functionStorage 'Microsoft.Storage/storageAccounts@2025-06-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}

resource functionStorageTableService 'Microsoft.Storage/storageAccounts/tableServices@2025-06-01' = {
  name: 'default'
  parent: functionStorage
}

resource functionStorageQueueService 'Microsoft.Storage/storageAccounts/queueServices@2025-06-01' = {
  name: 'default'
  parent: functionStorage
}

resource functionStorageWorkQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2025-06-01' = {
  name: workQueueName
  parent: functionStorageQueueService
}

resource functionStorageLifecycleQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2025-06-01' = {
  name: lifecycleQueueName
  parent: functionStorageQueueService
}

resource functionStorageDedupeTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-06-01' = {
  name: dedupeTableName
  parent: functionStorageTableService
}

resource functionPlan 'Microsoft.Web/serverfarms@2025-03-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {}
}

resource functionApp 'Microsoft.Web/sites@2025-03-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  identity: {
    type: empty(bootstrapUserAssignedIdentityName) ? 'SystemAssigned' : 'SystemAssigned, UserAssigned'
    userAssignedIdentities: empty(bootstrapUserAssignedIdentityName)
      ? null
      : {
          '${bootstrapIdentityResourceId}': {}
        }
  }
  properties: {
    httpsOnly: true
    serverFarmId: functionPlan.id
    siteConfig: {
      appSettings: concat(
        [
          {
            name: 'AzureWebJobsStorage'
            value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};AccountKey=${functionStorage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
          }
          {
            name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
            value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};AccountKey=${functionStorage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
          }
          {
            name: 'WEBSITE_CONTENTSHARE'
            value: toLower('${functionAppName}-content')
          }
          {
            name: 'FUNCTIONS_EXTENSION_VERSION'
            value: '~4'
          }
          {
            name: 'FUNCTIONS_WORKER_RUNTIME'
            value: 'powershell'
          }
          {
            name: 'DEDUPE_ENABLED'
            value: 'true'
          }
          {
            name: 'DEDUPE_TABLE_NAME'
            value: dedupeTableName
          }
          {
            name: 'DEDUPE_STORAGE_ACCOUNT_NAME'
            value: functionStorage.name
          }
          {
            name: 'DEDUPE_ENDPOINT_SUFFIX'
            value: environment().suffixes.storage
          }
          {
            name: 'WORK_QUEUE_NAME'
            value: workQueueName
          }
          {
            name: 'LIFECYCLE_QUEUE_NAME'
            value: lifecycleQueueName
          }
          // Identity-based connection for Storage Queue triggers/bindings.
          // See: https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference#common-properties-for-identity-based-connections
          {
            name: 'WorkQueue__queueServiceUri'
            value: functionStorage.properties.primaryEndpoints.queue
          }
          {
            name: 'WorkQueue__credential'
            value: 'managedidentity'
          }
        ],
        empty(bootstrapUserAssignedIdentityName)
          ? []
          : [
              {
                name: 'MANAGED_IDENTITY_CLIENT_ID'
                value: bootstrapIdentityClientId
              }
            ]
      )
    }
  }
}

// Data-plane RBAC for Table Storage access via the Function's managed identity.
// Built-in role: Storage Table Data Contributor
// See: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
var storageTableDataContributorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
)

resource functionAppStorageTableDataContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, functionApp.id, storageTableDataContributorRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageTableDataContributorRoleDefinitionId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Data-plane RBAC for Queue access via the Function's managed identity.
// Built-in roles:
// - Storage Queue Data Message Processor (trigger)
// - Storage Queue Data Message Sender (output)
var storageQueueDataMessageProcessorRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '8a0f0c08-91a1-4084-bc3d-661d67233fed'
)

var storageQueueDataMessageSenderRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a'
)

resource functionAppStorageQueueDataMessageProcessor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, functionApp.id, storageQueueDataMessageProcessorRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageQueueDataMessageProcessorRoleDefinitionId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource functionAppStorageQueueDataMessageSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(functionStorage.id, functionApp.id, storageQueueDataMessageSenderRoleDefinitionId)
  scope: functionStorage
  properties: {
    roleDefinitionId: storageQueueDataMessageSenderRoleDefinitionId
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

var deployedFunctionResourceId = '${functionApp.id}/functions/${functionName}'
var effectiveFunctionResourceId = !empty(functionResourceId) ? functionResourceId : deployedFunctionResourceId

var shouldBootstrapGraph = !empty(partnerTopicName) && !empty(bootstrapUserAssignedIdentityName)
var shouldCreatePartnerTopicSubscription = !empty(partnerTopicName) && !empty(effectiveFunctionResourceId)

resource partnerConfiguration 'Microsoft.EventGrid/partnerConfigurations@2025-02-15' = {
  name: partnerConfigurationName
  location: 'global'
  properties: shouldAuthorizePartner
    ? {
        partnerAuthorization: {
          defaultMaximumExpirationTimeInDays: 7
          authorizedPartnersList: [
            {
              // Schema supports identifying the partner by immutable ID and/or name.
              // The authorizationExpirationTimeInUtc is recommended for clarity.
              ...authorizedPartnerEntry
            }
          ]
        }
      }
    : {}
}

resource partnerTopic 'Microsoft.EventGrid/partnerTopics@2025-02-15' existing = if (shouldCreatePartnerTopicSubscription) {
  name: partnerTopicName
}

resource partnerTopicEventSubscription 'Microsoft.EventGrid/partnerTopics/eventSubscriptions@2025-02-15' = if (shouldCreatePartnerTopicSubscription) {
  name: partnerTopicEventSubscriptionName
  parent: partnerTopic
  dependsOn: shouldBootstrapGraph
    ? [
        activatePartnerTopic
      ]
    : []
  properties: {
    destination: {
      endpointType: 'AzureFunction'
      properties: {
        resourceId: effectiveFunctionResourceId
      }
    }
    eventDeliverySchema: 'CloudEventSchemaV1_0'
  }
}

// --- Imperative bootstrap via deployment scripts ---
// Notes:
// - Uses AzureCLI deployment scripts and runs pwsh scripts from this repo inline.
// - Requires a user-assigned managed identity (bootstrapUserAssignedIdentityName) that is already granted the required Microsoft Graph application roles.

resource createGraphSubscription 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'create-graph-subscription'
  location: location
  kind: 'AzureCLI'
  identity: shouldBootstrapGraph
    ? {
        type: 'UserAssigned'
        userAssignedIdentities: {
          '${bootstrapIdentityResourceId}': {}
        }
      }
    : null
  dependsOn: [
    partnerConfiguration
  ]
  properties: {
    azCliVersion: '2.59.0'
    timeout: 'PT45M'
    cleanupPreference: 'OnSuccess'
    retentionInterval: 'PT1H'
    scriptContent: '''
#!/bin/bash
set -euo pipefail

BOOTSTRAP_ENABLED='${string(shouldBootstrapGraph)}'
if [ "${BOOTSTRAP_ENABLED}" != "True" ] && [ "${BOOTSTRAP_ENABLED}" != "true" ]; then
  echo '{}' > "$AZ_SCRIPTS_OUTPUT_PATH"
  exit 0
fi

cat > ./New-GraphUsersSubscriptionToEventGrid.ps1 <<'PS1'
${loadTextContent('../scripts/New-GraphUsersSubscriptionToEventGrid.ps1')}
PS1

# Retry: Graph app role assignments may take time to become effective.
attempt=1
maxAttempts=20
while true; do
  set +e
  out=$(pwsh -NoProfile -File ./New-GraphUsersSubscriptionToEventGrid.ps1 \
    -AzureSubscriptionId "${subscription().subscriptionId}" \
    -ResourceGroupName "${resourceGroup().name}" \
    -PartnerTopicName "${partnerTopicName}" \
    -Location "${location}" \
    -UseAzCliGraphToken \
    -AsJson 2>&1)
  code=$?
  set -e

  if [ $code -eq 0 ]; then
    echo "$out" > ./subscription.json
    break
  fi

  if [ $attempt -ge $maxAttempts ]; then
    echo "Graph subscription creation failed after $maxAttempts attempts. Last error:" >&2
    echo "$out" >&2
    exit $code
  fi

  echo "Attempt $attempt/$maxAttempts failed; retrying in 30s..." >&2
  attempt=$((attempt + 1))
  sleep 30
done

clientState=$(jq -r '.clientState' ./subscription.json)
subscriptionId=$(jq -r '.subscriptionId' ./subscription.json)
expirationDateTime=$(jq -r '.expirationDateTime' ./subscription.json)

az functionapp config appsettings set \
  --resource-group "${resourceGroup().name}" \
  --name "${functionAppName}" \
  --settings "GRAPH_CLIENT_STATE=${clientState}" \
  --only-show-errors \
  >/dev/null

partnerTopicUrl="${environment().resourceManager}subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroup().name}/providers/Microsoft.EventGrid/partnerTopics/${partnerTopicName}?api-version=2025-02-15"

# Wait for Graph to create the partner topic resource (eventual consistency)
deadline=$((SECONDS + 600))
while [ $SECONDS -lt $deadline ]; do
  if az rest --method GET --url "$partnerTopicUrl" --only-show-errors >/dev/null 2>&1; then
    break
  fi
  sleep 10
done

partnerTopicId=$(az rest --method GET --url "$partnerTopicUrl" --query id -o tsv --only-show-errors 2>/dev/null || true)

jq -n -c \
  --arg subscriptionId "$subscriptionId" \
  --arg clientState "$clientState" \
  --arg expirationDateTime "$expirationDateTime" \
  --arg partnerTopicId "$partnerTopicId" \
  '{subscriptionId: $subscriptionId, clientState: $clientState, expirationDateTime: $expirationDateTime, partnerTopicId: $partnerTopicId}' \
  > "$AZ_SCRIPTS_OUTPUT_PATH"
'''
  }
}

resource activatePartnerTopic 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'activate-partner-topic'
  location: location
  kind: 'AzureCLI'
  identity: shouldBootstrapGraph
    ? {
        type: 'UserAssigned'
        userAssignedIdentities: {
          '${bootstrapIdentityResourceId}': {}
        }
      }
    : null
  dependsOn: [
    createGraphSubscription
  ]
  properties: {
    azCliVersion: '2.59.0'
    timeout: 'PT30M'
    cleanupPreference: 'OnSuccess'
    retentionInterval: 'PT1H'
    scriptContent: '''
#!/bin/bash
set -euo pipefail

BOOTSTRAP_ENABLED='${string(shouldBootstrapGraph)}'
if [ "${BOOTSTRAP_ENABLED}" != "True" ] && [ "${BOOTSTRAP_ENABLED}" != "true" ]; then
  echo '{}' > "$AZ_SCRIPTS_OUTPUT_PATH"
  exit 0
fi

cat > ./Activate-EventGridPartnerTopic.ps1 <<'PS1'
${loadTextContent('../scripts/Activate-EventGridPartnerTopic.ps1')}
PS1

pwsh -NoProfile -File ./Activate-EventGridPartnerTopic.ps1 \
  -AzureSubscriptionId "${subscription().subscriptionId}" \
  -ResourceGroupName "${resourceGroup().name}" \
  -PartnerTopicName "${partnerTopicName}" \
  -AsJson \
  > ./activation.json

jq -c '{activation: .}' ./activation.json > "$AZ_SCRIPTS_OUTPUT_PATH"
'''
  }
}

output partnerConfigurationId string = partnerConfiguration.id
output functionAppId string = functionApp.id
output functionResourceIdOut string = effectiveFunctionResourceId
output partnerTopicEventSubscriptionId string = shouldCreatePartnerTopicSubscription
  ? partnerTopicEventSubscription.id
  : ''

output bootstrapIdentityName string = bootstrapUserAssignedIdentityName
output bootstrapIdentityClientId string = bootstrapIdentityClientId
output bootstrapIdentityPrincipalId string = bootstrapIdentityPrincipalId
output graphSubscription object = createGraphSubscription.properties.outputs
output partnerTopicActivation object = activatePartnerTopic.properties.outputs
