param(
    [Parameter(Mandatory = $true)]
    [object]$QueueItem,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../Modules/GovernanceAutomation/GovernanceAutomation.psm1'

Remove-Module -Name 'GovernanceAutomation' -Force -ErrorAction SilentlyContinue
Import-Module -Name $modulePath -Force -ErrorAction Stop

function Get-QueueItemText {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    if ($InputObject -is [byte[]]) {
        return [System.Text.Encoding]::UTF8.GetString($InputObject)
    }

    $text = [string]$InputObject
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $text
    }

    $trimmed = $text.Trim()
    if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
        return $trimmed
    }

    try {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($trimmed))
        $decodedTrimmed = $decoded.Trim()
        if ($decodedTrimmed.StartsWith('{') -or $decodedTrimmed.StartsWith('[')) {
            return $decodedTrimmed
        }
    }
    catch {
        # Ignore base64 decode failures; fall back to raw text.
    }

    return $trimmed
}

$queueItemType = if ($null -eq $QueueItem) { '<null>' } else { $QueueItem.GetType().FullName }
$queueText = Get-QueueItemText -InputObject $QueueItem

$workItem = $null
try {
    $workItem = $queueText | ConvertFrom-Json -Depth 32
}
catch {
    Write-Information -MessageData ([pscustomobject]@{
            message        = 'Queue item was not valid JSON; skipping'
            queueItemType  = $queueItemType
            payloadFirstCh = if ([string]::IsNullOrEmpty($queueText)) { '' } else { $queueText.Substring(0, 1) }
        })
    return
}

$event = $workItem.payload.event

Write-Information -MessageData ([pscustomobject]@{
        message       = 'Dequeued lifecycle work item'
        schemaVersion = $workItem.schemaVersion
        kind          = $workItem.kind
        correlationId = $workItem.correlationId
        dequeueCount  = $TriggerMetadata.DequeueCount
        sourceId      = $workItem.source.id
        sourceType    = $workItem.source.eventType
        sourceSubject = $workItem.source.subject
    })

if (-not (Test-IsGraphLifecycleEvent -EventGridEvent $event)) {
    Write-Information -MessageData ([pscustomobject]@{
            message       = 'Non-lifecycle event received on lifecycle queue; skipping'
            correlationId = $workItem.correlationId
        })
    return
}

$items = @(Get-GraphNotificationItems -EventGridEvent $event)
$lifecycleItems = @($items | Where-Object { $_.PSObject.Properties.Name -contains 'lifecycleEvent' -and -not [string]::IsNullOrWhiteSpace([string]$_.lifecycleEvent) })

if ($lifecycleItems.Count -eq 0) {
    Write-Information -MessageData ([pscustomobject]@{
            message       = 'Lifecycle queue item contained no lifecycle notifications; skipping'
            correlationId = $workItem.correlationId
        })
    return
}

$expectedClientState = $env:GRAPH_CLIENT_STATE
if (-not [string]::IsNullOrWhiteSpace($expectedClientState)) {
    $mismatched = @(
        $lifecycleItems | Where-Object {
            ($_.PSObject.Properties.Name -contains 'clientState') -and ([string]$_.clientState -ne $expectedClientState)
        }
    )

    if ($mismatched.Count -gt 0) {
        Write-Information -MessageData ([pscustomobject]@{
                message       = 'Lifecycle notification clientState mismatch; skipping'
                correlationId = $workItem.correlationId
            })
        return
    }
}
else {
    Write-Information -MessageData ([pscustomobject]@{
            message       = 'GRAPH_CLIENT_STATE not set; proceeding without lifecycle clientState validation'
            correlationId = $workItem.correlationId
        })
}

$renewMinutes = 60

$renewMinutesSetting = $env:GRAPH_SUBSCRIPTION_RENEWAL_MINUTES
if ([string]::IsNullOrWhiteSpace($renewMinutesSetting)) {
    $renewMinutesSetting = $env:GRAPH_SUBSCRIPTION_RENEW_MINUTES
}

if (-not [string]::IsNullOrWhiteSpace($renewMinutesSetting)) {
    $parsed = 0
    if ([int]::TryParse($renewMinutesSetting, [ref]$parsed) -and $parsed -gt 0) {
        $renewMinutes = $parsed
    }
}

$subscriptionIds = @(
    $lifecycleItems |
    Where-Object { $_.PSObject.Properties.Name -contains 'subscriptionId' -and -not [string]::IsNullOrWhiteSpace([string]$_.subscriptionId) } |
    Select-Object -ExpandProperty subscriptionId -Unique
)

foreach ($subscriptionId in $subscriptionIds) {
    $eventsForSub = @($lifecycleItems | Where-Object { [string]$_.subscriptionId -eq $subscriptionId })
    $lifecycleEvents = @($eventsForSub | Select-Object -ExpandProperty lifecycleEvent -Unique)

    Write-Information -MessageData ([pscustomobject]@{
            message        = 'Received Graph lifecycle event'
            correlationId  = $workItem.correlationId
            subscriptionId = $subscriptionId
            lifecycleEvent = ($lifecycleEvents -join ',')
        })

    $requiresReauth = $false
    foreach ($evt in $lifecycleEvents) {
        if ([string]$evt -eq 'microsoft.graph.subscriptionReauthorizationRequired') {
            $requiresReauth = $true
        }
    }

    if (-not $requiresReauth) {
        Write-Information -MessageData ([pscustomobject]@{
                message        = 'Lifecycle event does not require reauthorize; no action taken'
                correlationId  = $workItem.correlationId
                subscriptionId = $subscriptionId
            })
        continue
    }

    $null = Invoke-GraphSubscriptionReauthorize -SubscriptionId $subscriptionId
    Write-Information -MessageData ([pscustomobject]@{
            message        = 'Graph subscription reauthorized'
            correlationId  = $workItem.correlationId
            subscriptionId = $subscriptionId
            operation      = 'reauthorize'
        })

    $newExpiration = (Get-Date).ToUniversalTime().AddMinutes($renewMinutes).ToString('o')
    $null = Set-GraphSubscriptionExpiration -SubscriptionId $subscriptionId -ExpirationDateTime $newExpiration

    Write-Information -MessageData ([pscustomobject]@{
            message            = 'Graph subscription renewed'
            correlationId      = $workItem.correlationId
            subscriptionId     = $subscriptionId
            operation          = 'renew'
            expirationDateTime = $newExpiration
        })
}
