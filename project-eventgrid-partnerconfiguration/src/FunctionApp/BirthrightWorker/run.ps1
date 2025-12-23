param(
    [Parameter(Mandatory = $true)]
    [string]$QueueItem,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module -Name GovernanceAutomation -Force -ErrorAction Stop

$policyPath = if (-not [string]::IsNullOrWhiteSpace($env:POLICY_PATH)) { $env:POLICY_PATH } else { 'policy/policy.json' }
$policy = Get-Policy -PolicyPath $policyPath

$workItem = $QueueItem | ConvertFrom-Json -Depth 32

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
