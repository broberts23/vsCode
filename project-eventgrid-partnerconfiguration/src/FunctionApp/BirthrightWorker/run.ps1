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

        function Get-OptionalPropertyValue {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [AllowNull()]
                [object]$Object,

                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$Name
            )

            if ($null -eq $Object) {
                return $null
            }

            if ($Object -is [System.Collections.IDictionary]) {
                if ($Object.Contains($Name)) {
                    return $Object[$Name]
                }
                return $null
            }

            $prop = $Object.PSObject.Properties[$Name]
            if ($null -eq $prop) {
                return $null
            }
            return $prop.Value
        }

        function ConvertTo-UtcDateTime {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $false)]
                [AllowNull()]
                [object]$Value
            )

            if ($null -eq $Value) {
                return $null
            }

            try {
                if ($Value -is [DateTime]) {
                    $dt = [DateTime]$Value
                    if ($dt.Kind -eq [DateTimeKind]::Utc) { return $dt }
                    return $dt.ToUniversalTime()
                }

                $text = [string]$Value
                if ([string]::IsNullOrWhiteSpace($text)) {
                    return $null
                }

                return ([DateTime]::Parse(
                        $text,
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [System.Globalization.DateTimeStyles]::RoundtripKind
                    )).ToUniversalTime()
            }
            catch {
                return $null
            }
        }

        function Resolve-UserIdFromWorkItem {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [object]$WorkItem
            )

            $source = Get-OptionalPropertyValue -Object $WorkItem -Name 'source'
            $resourceId = [string](Get-OptionalPropertyValue -Object $source -Name 'resourceId')
            if (-not [string]::IsNullOrWhiteSpace($resourceId)) {
                return $resourceId
            }

            $subject = [string](Get-OptionalPropertyValue -Object $source -Name 'subject')
            if (-not [string]::IsNullOrWhiteSpace($subject)) {
                $m = [regex]::Match($subject, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')
                if ($m.Success) {
                    return $m.Groups[1].Value
                }
            }

            return ''
        }

        function Get-GraphUserById {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$UserId
            )

            $uri = "https://graph.microsoft.com/v1.0/users/$UserId?`$select=id,userPrincipalName,userType,createdDateTime,accountEnabled"
            return (Invoke-GraphRequest -Method 'GET' -Uri $uri)
        }

        function Test-IsNewUserFromEvent {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [object]$User,

                [Parameter(Mandatory = $true)]
                [object]$WorkItem,

                [Parameter(Mandatory = $false)]
                [int]$MaxMinutesFromCreate = 30
            )

            $source = Get-OptionalPropertyValue -Object $WorkItem -Name 'source'
            $eventTimeUtc = ConvertTo-UtcDateTime -Value (Get-OptionalPropertyValue -Object $source -Name 'eventTime')
            if ($null -eq $eventTimeUtc) {
                $eventTimeUtc = (Get-Date).ToUniversalTime()
            }

            $createdUtc = ConvertTo-UtcDateTime -Value (Get-OptionalPropertyValue -Object $User -Name 'createdDateTime')
            if ($null -eq $createdUtc) {
                return $false
            }

            # Graph user subscriptions deliver user creation as an 'updated' notification.
            # To keep updates-only events safe, we treat an event as "new user" only when the user's
            # createdDateTime is very close to the event time.
            $deltaMinutes = ($eventTimeUtc - $createdUtc).TotalMinutes
            if ($deltaMinutes -ge 0 -and $deltaMinutes -le $MaxMinutesFromCreate) {
                return $true
            }

            # Allow a small clock-skew / ordering tolerance where createdDateTime appears slightly after eventTime.
            if ($deltaMinutes -lt 0 -and ([math]::Abs($deltaMinutes) -le 5)) {
                return $true
            }

            return $false
        }

        function Test-IsUserTypeMatch {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [AllowNull()]
                [object]$Assignment,

                [Parameter(Mandatory = $true)]
                [AllowNull()]
                [object]$User
            )

            if ($null -eq $Assignment) {
                return $true
            }

            $when = $null
            if ($Assignment -is [System.Collections.IDictionary]) {
                if ($Assignment.Contains('when')) { $when = $Assignment['when'] }
            }
            else {
                $when = Get-OptionalPropertyValue -Object $Assignment -Name 'when'
            }

            $requiredUserType = [string](Get-OptionalPropertyValue -Object $when -Name 'userType')
            if ([string]::IsNullOrWhiteSpace($requiredUserType)) {
                return $true
            }

            $actualUserType = [string](Get-OptionalPropertyValue -Object $User -Name 'userType')
            if ([string]::IsNullOrWhiteSpace($actualUserType)) {
                return $false
            }

            return ($requiredUserType.Trim().ToLowerInvariant() -eq $actualUserType.Trim().ToLowerInvariant())
        }

        function Test-GroupHasMember {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$GroupId,

                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$UserId
            )

            $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id&`$filter=id eq '$UserId'"
            $result = Invoke-GraphRequest -Method 'GET' -Uri $uri
            $items = @()
            if ($null -ne $result -and ($result.PSObject.Properties.Name -contains 'value')) {
                $items = @($result.value)
            }
            return ($items.Count -gt 0)
        }

        function Add-UserToGroup {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$GroupId,

                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$UserId
            )

            $uri = "https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref"
            $body = @{
                '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
            }

            $null = Invoke-GraphRequest -Method 'POST' -Uri $uri -Body $body
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

        $birthrightsMode = if ($null -ne $policy.birthrights -and ($policy.birthrights.PSObject.Properties.Name -contains 'mode')) { [string]$policy.birthrights.mode } else { 'detect' }
        if ($birthrightsMode.Trim().ToLowerInvariant() -ne 'remediate') {
            Write-Information -MessageData ([pscustomobject]@{
                    message         = 'Birthrights mode is detect; no Graph changes made'
                    birthrightsMode = $birthrightsMode
                })
            return
        }

        if ($configuredGroupIds.Count -eq 0) {
            Write-Information -MessageData ([pscustomobject]@{
                    message = 'Birthrights remediate enabled but no groups configured; skipping'
                })
            return
        }

        $userId = Resolve-UserIdFromWorkItem -WorkItem $workItem
        if ([string]::IsNullOrWhiteSpace($userId)) {
            Write-Information -MessageData ([pscustomobject]@{
                    message = 'Birthrights remediate enabled but userId could not be resolved from event; skipping'
                })
            return
        }

        $user = $null
        try {
            $user = Get-GraphUserById -UserId $userId
        }
        catch {
            Write-Error -MessageData ([pscustomobject]@{
                    message = 'Failed to load user from Microsoft Graph'
                    userId  = $userId
                    error   = $_.Exception.Message
                })
            throw
        }

        $newUserWindowMinutes = 30
        if (-not [string]::IsNullOrWhiteSpace($env:BIRTHRIGHT_NEW_USER_WINDOW_MINUTES)) {
            $parsed = 0
            if ([int]::TryParse([string]$env:BIRTHRIGHT_NEW_USER_WINDOW_MINUTES, [ref]$parsed) -and $parsed -gt 0 -and $parsed -le 1440) {
                $newUserWindowMinutes = $parsed
            }
        }

        $isNewUser = Test-IsNewUserFromEvent -User $user -WorkItem $workItem -MaxMinutesFromCreate $newUserWindowMinutes
        if (-not $isNewUser) {
            # Graph user change notifications don't support 'created' changeType; user creation arrives as 'updated'.
            # We gate birthrights using createdDateTime proximity so routine updates don't cause changes.
            Write-Information -MessageData ([pscustomobject]@{
                    message              = 'User event is not treated as newly created; no birthright changes applied'
                    userId               = $userId
                    userPrincipalName    = [string](Get-OptionalPropertyValue -Object $user -Name 'userPrincipalName')
                    createdDateTime      = [string](Get-OptionalPropertyValue -Object $user -Name 'createdDateTime')
                    eventTime            = [string](Get-OptionalPropertyValue -Object (Get-OptionalPropertyValue -Object $workItem -Name 'source') -Name 'eventTime')
                    newUserWindowMinutes = $newUserWindowMinutes
                })
            return
        }

        # Apply group birthrights only for assignments that match the user.
        $effectiveGroupIds = @()

        function Add-EffectiveGroupIdsFromValue {
            [CmdletBinding()]
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
                    $effectiveGroupIds += $Value
                }
                return
            }

            if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
                foreach ($v in $Value) {
                    if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) {
                        $effectiveGroupIds += $v
                    }
                }
                return
            }
        }

        if ($null -ne $policy.birthrights -and $null -ne $policy.birthrights.PSObject.Properties['addToGroups']) {
            Add-EffectiveGroupIdsFromValue -Value $policy.birthrights.addToGroups
        }

        foreach ($assignment in $assignments) {
            if (-not (Test-IsUserTypeMatch -Assignment $assignment -User $user)) {
                continue
            }

            if ($assignment -is [System.Collections.IDictionary]) {
                foreach ($k in @('addToGroups', 'groupIds', 'groups')) {
                    if ($assignment.Contains($k)) {
                        Add-EffectiveGroupIdsFromValue -Value $assignment[$k]
                        break
                    }
                }
            }
            else {
                foreach ($k in @('addToGroups', 'groupIds', 'groups')) {
                    $v = Get-OptionalPropertyValue -Object $assignment -Name $k
                    if ($null -ne $v) {
                        Add-EffectiveGroupIdsFromValue -Value $v
                        break
                    }
                }
            }
        }

        $effectiveGroupIds = @(
            $effectiveGroupIds |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
        )

        if ($effectiveGroupIds.Count -eq 0) {
            Write-Information -MessageData ([pscustomobject]@{
                    message = 'Birthrights remediate enabled but no matching assignments/groups for this user; skipping'
                    userId  = $userId
                })
            return
        }

        # Optimization: use the existing Table Storage dedupe table as a lightweight "processed" marker.
        # This avoids re-checking Graph group membership (and re-posting) on follow-up user 'updated' events
        # that may be triggered indirectly (for example, by directory changes around group membership).
        $markerEnabled = ($env:DEDUPE_ENABLED -eq 'true')
        $markerTableName = if (-not [string]::IsNullOrWhiteSpace($env:DEDUPE_TABLE_NAME)) { $env:DEDUPE_TABLE_NAME } else { 'DedupeKeys' }
        $markerStorageAccountName = $env:DEDUPE_STORAGE_ACCOUNT_NAME
        if ($markerEnabled -and [string]::IsNullOrWhiteSpace($markerStorageAccountName)) {
            throw 'DEDUPE_STORAGE_ACCOUNT_NAME must be set when DEDUPE_ENABLED=true.'
        }

        foreach ($groupId in $effectiveGroupIds) {
            try {
                if ($markerEnabled) {
                    $markerKey = "birthright|group:$groupId|user:$userId"
                    try {
                        if (Test-DedupeExists -DedupeKey $markerKey -StorageAccountName $markerStorageAccountName -EndpointSuffix $env:DEDUPE_ENDPOINT_SUFFIX -TableEndpoint $env:DEDUPE_TABLE_ENDPOINT -TableName $markerTableName) {
                            Write-Information -MessageData ([pscustomobject]@{
                                    message   = 'Birthright marker exists; skipping group processing'
                                    userId    = $userId
                                    groupId   = $groupId
                                    markerKey = $markerKey
                                })
                            continue
                        }
                    }
                    catch {
                        # Marker failures should not block enforcement; worst-case we do extra Graph work.
                        Write-Information -MessageData ([pscustomobject]@{
                                message = 'Failed to check birthright marker; continuing without marker optimization'
                                userId  = $userId
                                groupId = $groupId
                                error   = $_.Exception.Message
                            })
                    }
                }

                if (Test-GroupHasMember -GroupId $groupId -UserId $userId) {
                    Write-Information -MessageData ([pscustomobject]@{
                            message = 'User already a member of birthright group; no action'
                            userId  = $userId
                            groupId = $groupId
                        })

                    if ($markerEnabled) {
                        $markerKey = "birthright|group:$groupId|user:$userId"
                        try {
                            $null = Test-AndSetDedupe -DedupeKey $markerKey -StorageAccountName $markerStorageAccountName -EndpointSuffix $env:DEDUPE_ENDPOINT_SUFFIX -TableEndpoint $env:DEDUPE_TABLE_ENDPOINT -TableName $markerTableName
                        }
                        catch {
                            Write-Information -MessageData ([pscustomobject]@{
                                    message = 'Failed to set birthright marker after detecting membership; continuing'
                                    userId  = $userId
                                    groupId = $groupId
                                    error   = $_.Exception.Message
                                })
                        }
                    }
                    continue
                }

                Add-UserToGroup -GroupId $groupId -UserId $userId
                Write-Information -MessageData ([pscustomobject]@{
                        message = 'Added newly created user to birthright group'
                        userId  = $userId
                        groupId = $groupId
                    })

                if ($markerEnabled) {
                    $markerKey = "birthright|group:$groupId|user:$userId"
                    try {
                        $null = Test-AndSetDedupe -DedupeKey $markerKey -StorageAccountName $markerStorageAccountName -EndpointSuffix $env:DEDUPE_ENDPOINT_SUFFIX -TableEndpoint $env:DEDUPE_TABLE_ENDPOINT -TableName $markerTableName
                    }
                    catch {
                        Write-Information -MessageData ([pscustomobject]@{
                                message = 'Failed to set birthright marker after adding membership; continuing'
                                userId  = $userId
                                groupId = $groupId
                                error   = $_.Exception.Message
                            })
                    }
                }
            }
            catch {
                Write-Error -MessageData ([pscustomobject]@{
                        message = 'Failed to add user to birthright group'
                        userId  = $userId
                        groupId = $groupId
                        error   = $_.Exception.Message
                    })
                throw
            }
        }
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