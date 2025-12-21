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
        message = 'Received Event Grid event'
        dedupeKey = $dedupeKey
        eventId = $eventId
        eventType = $eventType
        subject = $subject
        eventTime = $eventTime
        mode = $mode
    }
)

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
        message = 'Policy rule matched'
        ruleName = $selectedRule.name
        actionType = $selectedRule.action.type
        steps = $selectedRule.action.steps
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
