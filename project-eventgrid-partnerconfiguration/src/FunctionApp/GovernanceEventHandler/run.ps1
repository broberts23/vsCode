#PSScriptAnalyzer -IgnoreRule PSAvoidAssignmentToAutomaticVariable

param(
    [Parameter(Mandatory = $true)]
    [object]$EventGridEvent,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../Modules/GovernanceAutomation/GovernanceAutomation.psm1'

try {
    Remove-Module -Name 'GovernanceAutomation' -Force -ErrorAction SilentlyContinue
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}
catch {
    throw "Failed to import GovernanceAutomation module from '$modulePath'. Error: $($_.Exception.Message)"
}

$policyPath = if (-not [string]::IsNullOrWhiteSpace($env:POLICY_PATH)) { $env:POLICY_PATH } else { 'policy/policy.json' }

# Event Grid trigger can deliver a batch (array) of events.
# Normalize to an array so we handle both single-event and batched deliveries.
$events = @($EventGridEvent)

$workItemPayloads = @()
$lifecycleWorkItemPayloads = @()
$duplicateCount = 0

$dedupeEnabled = ($env:DEDUPE_ENABLED -eq 'true')
foreach ($evt in $events) {
    if ($null -eq $evt) {
        continue
    }

    if ($dedupeEnabled) {
        $tableName = if (-not [string]::IsNullOrWhiteSpace($env:DEDUPE_TABLE_NAME)) { $env:DEDUPE_TABLE_NAME } else { 'DedupeKeys' }
        $accountName = $env:DEDUPE_STORAGE_ACCOUNT_NAME
        if ([string]::IsNullOrWhiteSpace($accountName)) {
            throw 'DEDUPE_STORAGE_ACCOUNT_NAME must be set when DEDUPE_ENABLED=true.'
        }

        $dedupeKey = Get-DedupeKey -Event $evt
        $isDuplicate = Test-AndSetDedupe -DedupeKey $dedupeKey -StorageAccountName $accountName -EndpointSuffix $env:DEDUPE_ENDPOINT_SUFFIX -TableEndpoint $env:DEDUPE_TABLE_ENDPOINT -TableName $tableName
        if ($isDuplicate) {
            $duplicateCount++
            Write-Information -MessageData ([pscustomobject]@{
                    message   = 'Duplicate event detected; skipping processing'
                    dedupeKey = $dedupeKey
                })
            continue
        }
    }

    $workItem = New-GovernanceWorkItem -EventGridEvent $evt -PolicyPath $policyPath
    $isLifecycle = Test-IsGraphLifecycleEvent -EventGridEvent $evt

    if ($isLifecycle) {
        $lifecycleWorkItemPayloads += ($workItem | ConvertTo-Json -Depth 16 -Compress)
    }
    else {
        $workItemPayloads += ($workItem | ConvertTo-Json -Depth 16 -Compress)
    }
}

if ($lifecycleWorkItemPayloads.Count -gt 0) {
    Push-OutputBinding -Name lifecycleWorkItem -Value $lifecycleWorkItemPayloads
}

if ($workItemPayloads.Count -gt 0) {
    Push-OutputBinding -Name workItem -Value $workItemPayloads
}

Write-Information -MessageData ([pscustomobject]@{
        message           = 'Enqueued governance work items'
        totalEvents       = $events.Count
        enqueuedWork      = $workItemPayloads.Count
        enqueuedLifecycle = $lifecycleWorkItemPayloads.Count
        duplicates        = $duplicateCount
    })

return
