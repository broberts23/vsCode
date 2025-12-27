param(
    [Parameter(Mandatory = $true)]
    [object]$QueueItem,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module -Name GovernanceAutomation -Force -ErrorAction Stop

$policyPath = if (-not [string]::IsNullOrWhiteSpace($env:POLICY_PATH)) { $env:POLICY_PATH } else { 'policy/policy.json' }
$policy = Get-Policy -PolicyPath $policyPath

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

    # Some hosts/clients encode queue messages as base64; try decoding.
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

Write-Information -MessageData ([pscustomobject]@{
        message       = 'Dequeued governance work item'
        schemaVersion = $workItem.schemaVersion
        kind          = $workItem.kind
        correlationId = $workItem.correlationId
        dequeueCount  = $TriggerMetadata.DequeueCount
        sourceId      = $workItem.source.id
        sourceType    = $workItem.source.eventType
        sourceSubject = $workItem.source.subject
    })

# Step 4 (birthright detection + live Graph mutations) intentionally NOT implemented.
# For blog/demo purposes, we only surface the policy intent in logs.
$birthrightsEnabled = $false
if ($null -ne $policy.PSObject.Properties['birthrights']) {
    $birthrightsEnabled = [bool]$policy.birthrights.enabled
}

if ($birthrightsEnabled) {
    $assignments = @($policy.birthrights.assignments)
    Write-Information -MessageData ([pscustomobject]@{
            message            = 'Birthrights policy present'
            mode               = $policy.birthrights.mode
            assignmentCount    = $assignments.Count
            configuredGroupIds = (@($assignments.addToGroups) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        })
}
else {
    Write-Information 'Birthrights policy not enabled; no action taken.'
}
