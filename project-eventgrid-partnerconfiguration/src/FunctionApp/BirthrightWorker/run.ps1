param(
    [Parameter(Mandatory = $true)]
    [object]$QueueItem,

    [Parameter(Mandatory = $false)]
    [hashtable]$TriggerMetadata
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

try {
    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath '../Modules/GovernanceAutomation/GovernanceAutomation.psm1'
    Remove-Module -Name 'GovernanceAutomation' -Force -ErrorAction SilentlyContinue
    Import-Module -Name $modulePath -Force -ErrorAction Stop
}
catch {
    Write-Information -MessageData ([pscustomobject]@{
            message = 'Failed to import GovernanceAutomation module; skipping queue message'
            error   = $_.Exception.Message
        })
    return
}

try {
    $policyPath = if (-not [string]::IsNullOrWhiteSpace($env:POLICY_PATH)) { $env:POLICY_PATH } else { 'policy/policy.json' }
    $policy = Get-Policy -PolicyPath $policyPath

    $queueItemType = if ($null -eq $QueueItem) { '<null>' } else { $QueueItem.GetType().FullName }

    if (-not ($QueueItem -is [System.Collections.IDictionary])) {
        Write-Information -MessageData ([pscustomobject]@{
                message       = 'Unexpected queue item shape; skipping'
                queueItemType = $queueItemType
                dequeueCount  = $TriggerMetadata.DequeueCount
            })
        return
    }

    foreach ($requiredKey in @('schemaVersion', 'kind', 'correlationId', 'payload')) {
        if (-not $QueueItem.Contains($requiredKey)) {
            Write-Information -MessageData ([pscustomobject]@{
                    message       = 'Queue item missing required key; skipping'
                    queueItemType = $queueItemType
                    missingKey    = $requiredKey
                    dequeueCount  = $TriggerMetadata.DequeueCount
                })
            return
        }
    }

    $workItem = $QueueItem

    Write-Information -MessageData ([pscustomobject]@{
            message       = 'Dequeued governance work item'
            whole         = $workItem
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
        $assignments = @()
        if ($null -ne $policy.birthrights -and $null -ne $policy.birthrights.PSObject.Properties['assignments']) {
            $assignments = @($policy.birthrights.assignments)
        }

        $configuredGroupIds = @()

        function Add-GroupIdsFromValue {
            param(
                [Parameter(Mandatory = $false)]
                [AllowNull()]
                [object]$Value
            )

            if ($null -eq $Value) {
                return
            }

            if ($Value -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace($Value)) {
                    $configuredGroupIds += $Value
                }
                return
            }

            if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
                foreach ($v in $Value) {
                    if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) {
                        $configuredGroupIds += $v
                    }
                }
                return
            }
        }

        # Support both:
        # - birthrights.assignments[*].addToGroups
        # - birthrights.addToGroups
        if ($null -ne $policy.birthrights -and $null -ne $policy.birthrights.PSObject.Properties['addToGroups']) {
            Add-GroupIdsFromValue -Value $policy.birthrights.addToGroups
        }

        foreach ($assignment in $assignments) {
            if ($null -eq $assignment) { continue }

            if ($assignment -is [System.Collections.IDictionary]) {
                foreach ($k in @('addToGroups', 'groupIds', 'groups')) {
                    if ($assignment.Contains($k)) {
                        Add-GroupIdsFromValue -Value $assignment[$k]
                        break
                    }
                }
                continue
            }

            if ($null -ne $assignment.PSObject.Properties['addToGroups']) {
                Add-GroupIdsFromValue -Value $assignment.addToGroups
                continue
            }
            if ($null -ne $assignment.PSObject.Properties['groupIds']) {
                Add-GroupIdsFromValue -Value $assignment.groupIds
                continue
            }
            if ($null -ne $assignment.PSObject.Properties['groups']) {
                Add-GroupIdsFromValue -Value $assignment.groups
                continue
            }
        }

        $configuredGroupIds = @(
            $configuredGroupIds |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
        )

        Write-Information -MessageData ([pscustomobject]@{
                message            = 'Birthrights policy present'
                mode               = if ($null -ne $policy.birthrights.PSObject.Properties['mode']) { $policy.birthrights.mode } else { '' }
                assignmentCount    = $assignments.Count
                configuredGroupIds = $configuredGroupIds
            })
    }
    else {
        Write-Information 'Birthrights policy not enabled; no action taken.'
    }
}
catch {
    Write-Error -MessageData ([pscustomobject]@{
            message = 'Error processing governance work item'
            error   = $_.Exception.Message
        })
    throw
}