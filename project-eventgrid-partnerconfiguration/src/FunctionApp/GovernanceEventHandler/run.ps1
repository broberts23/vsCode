#PSScriptAnalyzer -IgnoreRule PSAvoidAssignmentToAutomaticVariable

param(
    [Parameter(Mandatory = $true)]
    [object]$EventGridEvent,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Policy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyPath
    )

    if (-not (Test-Path -Path $PolicyPath -PathType Leaf)) {
        throw "Policy file not found at path: $PolicyPath"
    }

    $raw = Get-Content -Path $PolicyPath -Raw
    return ($raw | ConvertFrom-Json -Depth 32)
}

function Get-DedupeKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Event
    )

    $id = $Event.id
    $eventType = $Event.eventType
    $subject = $Event.subject

    if ([string]::IsNullOrWhiteSpace($id)) {
        # Fall back to a composite key if id is absent.
        $id = "$($Event.eventTime)-$subject-$eventType"
    }

    return "$eventType|$subject|$id"
}

function Test-IsBreakGlass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $false)]
        [string]$ObjectId
    )

    $upnList = @($Policy.breakGlass.userPrincipalNames)
    $idList = @($Policy.breakGlass.objectIds)

    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName) -and $upnList -contains $UserPrincipalName) {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($ObjectId) -and $idList -contains $ObjectId) {
        return $true
    }

    return $false
}

function Get-ManagedIdentityAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource = 'https://graph.microsoft.com/'
    )

    # Azure App Service / Azure Functions managed identity endpoint
    # - Modern: IDENTITY_ENDPOINT + IDENTITY_HEADER
    # - Legacy: MSI_ENDPOINT + MSI_SECRET

    if (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT) -and -not [string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER)) {
        $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01"
        $headers = @{
            'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER
        }

        $tokenResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
            throw 'Managed identity token response missing access_token.'
        }

        return $tokenResponse.access_token
    }

    if (-not [string]::IsNullOrWhiteSpace($env:MSI_ENDPOINT) -and -not [string]::IsNullOrWhiteSpace($env:MSI_SECRET)) {
        $uri = "$($env:MSI_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2017-09-01"
        $headers = @{
            'Secret' = $env:MSI_SECRET
        }

        $tokenResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
            throw 'Managed identity token response missing access_token.'
        }

        return $tokenResponse.access_token
    }

    throw 'Managed identity endpoint not available. This function must run in Azure with a system-assigned managed identity enabled.'
}

function Invoke-GraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [object]$Body
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }

    $jsonBody = $Body | ConvertTo-Json -Depth 16
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json' -Body $jsonBody
}

function Get-GraphLifecycleEventName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Event
    )

    if ($null -eq $Event.data) {
        return $null
    }

    # Graph lifecycle notifications include `lifecycleEvent`.
    $name = $Event.data.lifecycleEvent
    if (-not [string]::IsNullOrWhiteSpace($name)) {
        return [string]$name
    }

    return $null
}

function Get-GraphSubscriptionIdFromEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Event
    )

    if ($null -eq $Event.data) {
        return $null
    }

    $subscriptionId = $Event.data.subscriptionId

    if ([string]::IsNullOrWhiteSpace($subscriptionId) -and $null -ne $Event.data.subscription) {
        $subscriptionId = $Event.data.subscription.id
    }

    if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
        return $null
    }

    return [string]$subscriptionId
}

function Test-GraphClientState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Event
    )

    $expectedClientState = $env:GRAPH_CLIENT_STATE
    if ([string]::IsNullOrWhiteSpace($expectedClientState)) {
        # If not configured, do not enforce.
        return $true
    }

    $actualClientState = $Event.data.clientState
    if ([string]::IsNullOrWhiteSpace($actualClientState)) {
        return $false
    }

    return ($actualClientState -eq $expectedClientState)
}

function Invoke-GraphSubscriptionReauthorizeAndRenew {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $accessToken = Get-ManagedIdentityAccessToken -Resource 'https://graph.microsoft.com/'

    # Reauthorize is currently a beta-only endpoint.
    $reauthorizeUri = "https://graph.microsoft.com/beta/subscriptions/$SubscriptionId/reauthorize"
    $reauthorizeResult = Invoke-GraphRequest -Method POST -Uri $reauthorizeUri -AccessToken $accessToken

    Write-Information -MessageData (
        [pscustomobject]@{
            message        = 'Graph subscription reauthorized'
            subscriptionId = $SubscriptionId
            graphEndpoint  = 'beta'
            operation      = 'reauthorize'
            result         = $reauthorizeResult
        }
    )

    $renewMinutes = 40320 # 28 days
    if (-not [string]::IsNullOrWhiteSpace($env:GRAPH_SUBSCRIPTION_RENEW_MINUTES)) {
        $parsed = 0
        if ([int]::TryParse($env:GRAPH_SUBSCRIPTION_RENEW_MINUTES, [ref]$parsed) -and $parsed -gt 0) {
            $renewMinutes = $parsed
        }
    }

    $newExpiry = (Get-Date).ToUniversalTime().AddMinutes($renewMinutes).ToString('o')

    $renewUri = "https://graph.microsoft.com/v1.0/subscriptions/$SubscriptionId"
    $renewResult = Invoke-GraphRequest -Method PATCH -Uri $renewUri -AccessToken $accessToken -Body @{
        expirationDateTime = $newExpiry
    }

    Write-Information -MessageData (
        [pscustomobject]@{
            message            = 'Graph subscription renewed'
            subscriptionId     = $SubscriptionId
            graphEndpoint      = 'v1.0'
            operation          = 'renew'
            expirationDateTime = $newExpiry
            result             = $renewResult
        }
    )
}

# ---- Main ----

$policyPath = $env:POLICY_PATH
if ([string]::IsNullOrWhiteSpace($policyPath)) {
    $policyPath = 'policy/policy.json'
}

$mode = $env:MODE
if ([string]::IsNullOrWhiteSpace($mode)) {
    $mode = 'detect'
}

$policy = Get-Policy -PolicyPath $policyPath

$dedupeKey = Get-DedupeKey -Event $EventGridEvent

# Minimal event introspection (shape depends on publisher + schema)
$eventId = $EventGridEvent.id
$eventType = $EventGridEvent.eventType
$subject = $EventGridEvent.subject
$eventTime = $EventGridEvent.eventTime

Write-Information -MessageData (
    [pscustomobject]@{
        message   = 'Received Event Grid event'
        dedupeKey = $dedupeKey
        eventId   = $eventId
        eventType = $eventType
        subject   = $subject
        eventTime = $eventTime
        mode      = $mode
    }
)

# Handle Microsoft Graph subscription lifecycle notifications delivered via Event Grid.
$lifecycleEvent = Get-GraphLifecycleEventName -Event $EventGridEvent
if (-not [string]::IsNullOrWhiteSpace($lifecycleEvent)) {
    if (-not (Test-GraphClientState -Event $EventGridEvent)) {
        Write-Warning 'Graph lifecycle event failed clientState validation; ignoring.'
        return
    }

    $subscriptionId = Get-GraphSubscriptionIdFromEvent -Event $EventGridEvent
    if ([string]::IsNullOrWhiteSpace($subscriptionId)) {
        Write-Warning 'Graph lifecycle event missing subscriptionId; ignoring.'
        return
    }

    Write-Information -MessageData (
        [pscustomobject]@{
            message        = 'Received Graph lifecycle event'
            lifecycleEvent = $lifecycleEvent
            subscriptionId = $subscriptionId
        }
    )

    $normalized = $lifecycleEvent
    if ($normalized -eq 'microsoft.graph.subscriptionReauthorizationRequired' -or $normalized -eq 'reauthorizationRequired') {
        Invoke-GraphSubscriptionReauthorizeAndRenew -SubscriptionId $subscriptionId
        return
    }

    Write-Information "Graph lifecycle event '$lifecycleEvent' received; no action implemented for this event type."
    return
}

# TODO: Persist dedupe key with TTL (Storage Table / Cosmos / Redis) and short-circuit if already processed.

# TODO: Extract principal identifiers from event payload (varies by event type).
# Example placeholders:
$userPrincipalName = $null
$principalObjectId = $null

if (Test-IsBreakGlass -Policy $policy -UserPrincipalName $userPrincipalName -ObjectId $principalObjectId) {
    Write-Warning "Break-glass principal matched; skipping any remediation."
    return
}

# Policy evaluation stub:
# - Minimal scaffold chooses the first rule.
# - Expand later to match by eventType/subject/conditions.
$rules = @($policy.rules)
$selectedRule = if ($rules.Count -gt 0) { $rules[0] } else { $null }

if ($null -eq $selectedRule) {
    Write-Information "No policy rule matched; no action taken."
    return
}

Write-Information -MessageData (
    [pscustomobject]@{
        message    = 'Policy rule matched'
        ruleName   = $selectedRule.name
        actionType = $selectedRule.action.type
        steps      = $selectedRule.action.steps
    }
)

$shouldRemediate = ($mode -eq 'remediate') -and ($selectedRule.action.type -eq 'remediate')
if (-not $shouldRemediate) {
    Write-Information "Detect-only mode (or non-remediate rule); skipping remediation steps."
    return
}

# ---- Remediation stub ----
# TODO: Acquire Microsoft Graph token via client credentials and execute allowed operations.
# Guardrails: only mutate resources in allowLists.*

Write-Warning "Remediation is enabled, but this scaffold does not yet implement Graph actions."
