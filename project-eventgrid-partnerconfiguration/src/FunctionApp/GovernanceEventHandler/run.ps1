#PSScriptAnalyzer -IgnoreRule PSAvoidAssignmentToAutomaticVariable

param(
    [Parameter(Mandatory = $true)]
    [object]$EventGridEvent,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Ingress-only mode: validate/dedupe, enqueue work item, return.
# The remainder of this file contains legacy scaffold code and is intentionally unreachable.
try {
    Import-Module -Name GovernanceAutomation -Force -ErrorAction Stop
}
catch {
    throw "Failed to import GovernanceAutomation module. Ensure the module exists under src/FunctionApp/Modules and is deployed. Error: $($_.Exception.Message)"
}

$policyPath = if (-not [string]::IsNullOrWhiteSpace($env:POLICY_PATH)) { $env:POLICY_PATH } else { 'policy/policy.json' }

$dedupeEnabled = ($env:DEDUPE_ENABLED -eq 'true')
if ($dedupeEnabled) {
    $tableName = if (-not [string]::IsNullOrWhiteSpace($env:DEDUPE_TABLE_NAME)) { $env:DEDUPE_TABLE_NAME } else { 'DedupeKeys' }
    $accountName = $env:DEDUPE_STORAGE_ACCOUNT_NAME
    if ([string]::IsNullOrWhiteSpace($accountName)) {
        throw 'DEDUPE_STORAGE_ACCOUNT_NAME must be set when DEDUPE_ENABLED=true.'
    }

    $dedupeKey = Get-DedupeKey -Event $EventGridEvent
    $isDuplicate = Test-AndSetDedupe -DedupeKey $dedupeKey -StorageAccountName $accountName -EndpointSuffix $env:DEDUPE_ENDPOINT_SUFFIX -TableEndpoint $env:DEDUPE_TABLE_ENDPOINT -TableName $tableName
    if ($isDuplicate) {
        Write-Information -MessageData ([pscustomobject]@{
                message   = 'Duplicate event detected; skipping processing'
                dedupeKey = $dedupeKey
            })
        return
    }
}

$workItem = New-GovernanceWorkItem -EventGridEvent $EventGridEvent -PolicyPath $policyPath

$isLifecycle = Test-IsGraphLifecycleEvent -EventGridEvent $EventGridEvent
if ($isLifecycle) {
    Push-OutputBinding -Name lifecycleWorkItem -Value ($workItem | ConvertTo-Json -Depth 16 -Compress)
}
else {
    Push-OutputBinding -Name workItem -Value ($workItem | ConvertTo-Json -Depth 16 -Compress)
}

Write-Information -MessageData ([pscustomobject]@{
        message       = 'Enqueued governance work item'
        kind          = $workItem.kind
        schemaVersion = $workItem.schemaVersion
        correlationId = $workItem.correlationId
        isLifecycle   = $isLifecycle
    })

return
