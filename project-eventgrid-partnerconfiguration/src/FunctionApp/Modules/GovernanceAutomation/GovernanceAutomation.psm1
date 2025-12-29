Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FunctionAppRootPath {
    [CmdletBinding()]
    param()

    # Module lives at: <FunctionAppRoot>/Modules/GovernanceAutomation
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}

function Resolve-GovernancePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    $root = Get-FunctionAppRootPath
    return (Join-Path -Path $root -ChildPath $Path)
}

function Get-Policy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyPath
    )

    $resolved = Resolve-GovernancePath -Path $PolicyPath
    if (-not (Test-Path -Path $resolved -PathType Leaf)) {
        throw "Policy file not found at path: $resolved"
    }

    $raw = Get-Content -Path $resolved -Raw
    return ($raw | ConvertFrom-Json -Depth 32)
}

function Get-DedupeKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Event
    )

    # Defensive: the Event Grid trigger can hand us an array (batch). We expect a single event here.
    if ($Event -is [System.Array]) {
        if ($Event.Count -eq 1) {
            $Event = $Event[0]
        }
        else {
            throw "Get-DedupeKey expects a single event object; received an array of $($Event.Count)."
        }
    }

    # Event Grid can deliver in either EventGridSchema or CloudEvents 1.0.
    # - EventGridSchema: eventType, eventTime, topic
    # - CloudEvents:     type, time, source
    $id = if ($Event.PSObject.Properties.Name -contains 'id') { [string]$Event.id } else { '' }
    $type = if ($Event.PSObject.Properties.Name -contains 'eventType') { [string]$Event.eventType } elseif ($Event.PSObject.Properties.Name -contains 'type') { [string]$Event.type } else { '' }
    $subject = if ($Event.PSObject.Properties.Name -contains 'subject') { [string]$Event.subject } else { '' }
    $time = if ($Event.PSObject.Properties.Name -contains 'eventTime') { [string]$Event.eventTime } elseif ($Event.PSObject.Properties.Name -contains 'time') { [string]$Event.time } else { '' }

    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = "$time-$subject-$type"
    }

    $dedupeKey = "$type|$subject|$id"

    # If we still couldn't extract anything meaningful, fall back to hashing the full payload
    # to avoid pathological collisions like "||--".
    $idLooksEmpty = ([string]::IsNullOrWhiteSpace($id) -or $id -eq '--' -or $id -eq '-')
    if ([string]::IsNullOrWhiteSpace($type) -and [string]::IsNullOrWhiteSpace($subject) -and $idLooksEmpty) {
        $json = $Event | ConvertTo-Json -Depth 32 -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBytes = $sha256.ComputeHash($bytes)
        }
        finally {
            $sha256.Dispose()
        }
        $hashHex = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
        $dedupeKey = "hash:$hashHex"
    }

    return $dedupeKey
}

function ConvertTo-Sha256Hex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hashBytes = [System.Security.Cryptography.SHA256]::HashData($bytes)

    $builder = [System.Text.StringBuilder]::new()
    foreach ($b in $hashBytes) {
        [void]$builder.AppendFormat('{0:x2}', $b)
    }
    return $builder.ToString()
}

function Get-ManagedIdentityAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource = 'https://graph.microsoft.com/'
    )

    $clientId = $env:MANAGED_IDENTITY_CLIENT_ID
    $clientIdQuery = ''
    if (-not [string]::IsNullOrWhiteSpace($clientId)) {
        # App Service / Azure Functions local MSI endpoint supports client_id for user-assigned identity selection.
        # See: https://learn.microsoft.com/azure/app-service/overview-managed-identity?tabs=portal,http#rest-endpoint-reference
        $clientIdQuery = "&client_id=$([uri]::EscapeDataString($clientId))"
    }

    if (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT) -and -not [string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER)) {
        $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2019-08-01$clientIdQuery"
        $headers = @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER }

        $tokenResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
            throw 'Managed identity token response missing access_token.'
        }

        return $tokenResponse.access_token
    }

    if (-not [string]::IsNullOrWhiteSpace($env:MSI_ENDPOINT) -and -not [string]::IsNullOrWhiteSpace($env:MSI_SECRET)) {
        $uri = "$($env:MSI_ENDPOINT)?resource=$([uri]::EscapeDataString($Resource))&api-version=2017-09-01$clientIdQuery"
        $headers = @{ 'Secret' = $env:MSI_SECRET }

        $tokenResponse = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        if ([string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
            throw 'Managed identity token response missing access_token.'
        }

        return $tokenResponse.access_token
    }

    throw 'Managed identity endpoint variables not found. This function must run in Azure Functions/App Service with managed identity enabled.'
}

function Get-AzureStorageTableContextFromEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $false)]
        [string]$EndpointSuffix,

        [Parameter(Mandatory = $false)]
        [string]$TableEndpoint
    )

    $resolvedEndpointSuffix = $EndpointSuffix
    if ([string]::IsNullOrWhiteSpace($resolvedEndpointSuffix)) {
        $resolvedEndpointSuffix = 'core.windows.net'
    }

    $resolvedTableEndpoint = $TableEndpoint
    if ([string]::IsNullOrWhiteSpace($resolvedTableEndpoint)) {
        $resolvedTableEndpoint = "https://$StorageAccountName.table.$resolvedEndpointSuffix"
    }

    return [pscustomobject]@{
        AccountName   = $StorageAccountName
        TableEndpoint = $resolvedTableEndpoint.TrimEnd('/')
    }
}

function Invoke-AzureStorageTableRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'MERGE', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $false)]
        [string]$EndpointSuffix,

        [Parameter(Mandatory = $false)]
        [string]$TableEndpoint,

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [int[]]$AllowStatusCodes = @()
    )

    $ctx = Get-AzureStorageTableContextFromEnvironment -StorageAccountName $StorageAccountName -EndpointSuffix $EndpointSuffix -TableEndpoint $TableEndpoint
    $accessToken = Get-ManagedIdentityAccessToken -Resource 'https://storage.azure.com/'
    $date = (Get-Date).ToUniversalTime().ToString('R')

    $headers = @{
        'Authorization'         = "Bearer $accessToken"
        'x-ms-date'             = $date
        'x-ms-version'          = '2020-12-06'
        'DataServiceVersion'    = '3.0;NetFx'
        'MaxDataServiceVersion' = '3.0;NetFx'
        'Accept'                = 'application/json;odata=nometadata'
    }

    $uri = "$($ctx.TableEndpoint)/$Path"

    try {
        if ($null -eq $Body) {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        }

        $jsonBody = $Body | ConvertTo-Json -Depth 16
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $jsonBody
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            $statusCode = [int]$response.StatusCode
            if ($AllowStatusCodes -contains $statusCode) {
                return [pscustomobject]@{
                    StatusCode = $statusCode
                    Ignored    = $true
                }
            }
        }

        throw
    }
}

function Test-AndSetDedupe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DedupeKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $false)]
        [string]$EndpointSuffix,

        [Parameter(Mandatory = $false)]
        [string]$TableEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TableName
    )

    $hash = ConvertTo-Sha256Hex -Value $DedupeKey
    $partitionKey = $hash.Substring(0, 2)
    $rowKey = $hash

    $entity = @{
        PartitionKey = $partitionKey
        RowKey       = $rowKey
        DedupedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    }

    $result = Invoke-AzureStorageTableRequest -Method 'POST' -Path $TableName -StorageAccountName $StorageAccountName -EndpointSuffix $EndpointSuffix -TableEndpoint $TableEndpoint -Body $entity -AllowStatusCodes @(409)

    if ($null -ne $result -and $result.PSObject.Properties.Name -contains 'StatusCode' -and $result.StatusCode -eq 409) {
        return $true
    }

    return $false
}

function New-GovernanceWorkItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventGridEvent,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyPath
    )

    $policy = Get-Policy -PolicyPath $PolicyPath

    # Defensive: Event Grid trigger can deliver a batch (array). This function expects a single event.
    if ($EventGridEvent -is [System.Array]) {
        if ($EventGridEvent.Count -eq 1) {
            $EventGridEvent = $EventGridEvent[0]
        }
        else {
            throw "New-GovernanceWorkItem expects a single event object; received an array of $($EventGridEvent.Count)."
        }
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

        # Handle hashtables/dictionaries.
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($Name)) {
                return $Object[$Name]
            }
            return $null
        }

        # If we got JSON as a string, try to parse it.
        if ($Object -is [string]) {
            $text = [string]$Object
            $trimmed = $text.Trim()
            if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
                try {
                    $Object = $trimmed | ConvertFrom-Json -Depth 64
                }
                catch {
                    return $null
                }
            }
            else {
                return $null
            }
        }

        $prop = $Object.PSObject.Properties[$Name]
        if ($null -eq $prop) {
            return $null
        }

        return $prop.Value
    }

    function ConvertTo-Iso8601UtcString {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $false)]
            [AllowNull()]
            [object]$Value
        )

        if ($null -eq $Value) {
            return ''
        }

        if ($Value -is [datetime]) {
            return ([datetime]$Value).ToUniversalTime().ToString('o')
        }

        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) {
            return ''
        }

        $parsed = $null
        if ([datetime]::TryParse($text, [ref]$parsed)) {
            return $parsed.ToUniversalTime().ToString('o')
        }

        return $text
    }

    # Event Grid can deliver in either EventGridSchema or CloudEvents 1.0. Normalize both.
    # - EventGridSchema: eventType, eventTime, topic
    # - CloudEvents:     type, time, source
    $id = [string](Get-OptionalPropertyValue -Object $EventGridEvent -Name 'id')
    $eventType = [string](Get-OptionalPropertyValue -Object $EventGridEvent -Name 'eventType')
    if ([string]::IsNullOrWhiteSpace($eventType)) {
        $eventType = [string](Get-OptionalPropertyValue -Object $EventGridEvent -Name 'type')
    }

    $subject = [string](Get-OptionalPropertyValue -Object $EventGridEvent -Name 'subject')
    $eventTimeValue = (Get-OptionalPropertyValue -Object $EventGridEvent -Name 'eventTime')
    if ($null -eq $eventTimeValue -or ([string]$eventTimeValue).Length -eq 0) {
        $eventTimeValue = (Get-OptionalPropertyValue -Object $EventGridEvent -Name 'time')
    }
    $eventTime = ConvertTo-Iso8601UtcString -Value $eventTimeValue

    $topic = [string](Get-OptionalPropertyValue -Object $EventGridEvent -Name 'topic')
    if ([string]::IsNullOrWhiteSpace($topic)) {
        $topic = [string](Get-OptionalPropertyValue -Object $EventGridEvent -Name 'source')
    }

    # Microsoft Graph partner events (CloudEvents) commonly include details in data.*
    $data = Get-OptionalPropertyValue -Object $EventGridEvent -Name 'data'
    $changeType = [string](Get-OptionalPropertyValue -Object $data -Name 'changeType')
    $resource = [string](Get-OptionalPropertyValue -Object $data -Name 'resource')
    $tenantId = [string](Get-OptionalPropertyValue -Object $data -Name 'tenantId')
    $subscriptionId = [string](Get-OptionalPropertyValue -Object $data -Name 'subscriptionId')
    $subscriptionExpirationValue = (Get-OptionalPropertyValue -Object $data -Name 'subscriptionExpirationDateTime')
    $subscriptionExpirationDateTime = ConvertTo-Iso8601UtcString -Value $subscriptionExpirationValue
    $resourceData = Get-OptionalPropertyValue -Object $data -Name 'resourceData'
    $resourceId = [string](Get-OptionalPropertyValue -Object $resourceData -Name 'id')
    $organizationId = [string](Get-OptionalPropertyValue -Object $resourceData -Name 'organizationId')
    $odataType = [string](Get-OptionalPropertyValue -Object $resourceData -Name '@odata.type')
    $odataId = [string](Get-OptionalPropertyValue -Object $resourceData -Name '@odata.id')

    if ([string]::IsNullOrWhiteSpace($subject)) {
        if (-not [string]::IsNullOrWhiteSpace($resource)) {
            $subject = $resource
        }
        elseif (-not [string]::IsNullOrWhiteSpace($odataId)) {
            $subject = $odataId
        }
    }

    # If tenantId isn't included in data, try to extract it from the CloudEvents source.
    if ([string]::IsNullOrWhiteSpace($tenantId) -and -not [string]::IsNullOrWhiteSpace($topic)) {
        $m = [regex]::Match($topic, '/tenants/([0-9a-fA-F-]{36})(/|$)')
        if ($m.Success) {
            $tenantId = $m.Groups[1].Value
        }
    }

    return [pscustomobject]@{
        schemaVersion = 1
        kind          = 'eventgrid.v1'
        correlationId = ([guid]::NewGuid().ToString())
        enqueuedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        policy        = [pscustomobject]@{
            version = $policy.version
            mode    = $policy.mode
        }
        source        = [pscustomobject]@{
            id                             = $id
            eventType                      = $eventType
            subject                        = $subject
            eventTime                      = $eventTime
            topic                          = $topic
            changeType                     = $changeType
            resource                       = $resource
            resourceId                     = $resourceId
            tenantId                       = $tenantId
            organizationId                 = $organizationId
            subscriptionId                 = $subscriptionId
            subscriptionExpirationDateTime = $subscriptionExpirationDateTime
            odataType                      = $odataType
        }
        payload       = [pscustomobject]@{
            event = $EventGridEvent
        }
    }
}

function Get-GraphNotificationItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventGridEvent
    )

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

        # If we got JSON as a string, try to parse it.
        if ($Object -is [string]) {
            $text = [string]$Object
            $trimmed = $text.Trim()
            if ($trimmed.StartsWith('{') -or $trimmed.StartsWith('[')) {
                try {
                    $Object = $trimmed | ConvertFrom-Json -Depth 64
                }
                catch {
                    return $null
                }
            }
            else {
                return $null
            }
        }

        $prop = $Object.PSObject.Properties[$Name]
        if ($null -eq $prop) {
            return $null
        }

        return $prop.Value
    }

    # Graph change notifications (and lifecycle notifications) are typically shaped like:
    #   { "value": [ { ... }, { ... } ] }
    # When delivered through Event Grid Partner Topics, that payload is commonly in EventGridEvent.data
    # but we defensively probe a couple of common wrappers.
    $data = Get-OptionalPropertyValue -Object $EventGridEvent -Name 'data'
    $dataData = Get-OptionalPropertyValue -Object $data -Name 'data'
    $payload = Get-OptionalPropertyValue -Object $EventGridEvent -Name 'payload'
    $payloadData = Get-OptionalPropertyValue -Object $payload -Name 'data'

    # Also include the event itself as a candidate because some producers send the Graph payload directly.
    $candidates = @(
        $data,
        $dataData,
        $payload,
        $payloadData,
        $EventGridEvent
    )

    foreach ($candidate in $candidates) {
        if ($null -eq $candidate) {
            continue
        }

        $value = Get-OptionalPropertyValue -Object $candidate -Name 'value'
        if ($null -ne $value) {
            $items = @($value)
            if ($items.Count -gt 0) {
                # Use unary comma to prevent PowerShell from enumerating the array on the pipeline.
                return , $items
            }
        }
    }

    # Ensure callers always receive an array (even when empty) under StrictMode.
    return , @()
}

function Test-IsGraphLifecycleEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventGridEvent
    )

    # Force array semantics: Get-GraphNotificationItems can return no output, which would otherwise yield $null.
    $items = @(Get-GraphNotificationItems -EventGridEvent $EventGridEvent)
    if ($items.Count -eq 0) {
        return $false
    }

    foreach ($item in $items) {
        if ($null -ne $item -and ($item.PSObject.Properties.Name -contains 'lifecycleEvent')) {
            if (-not [string]::IsNullOrWhiteSpace([string]$item.lifecycleEvent)) {
                return $true
            }
        }
    }

    return $false
}

function Invoke-GraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [int[]]$AllowStatusCodes = @()
    )

    $token = Get-ManagedIdentityAccessToken -Resource 'https://graph.microsoft.com/'
    $headers = @{ Authorization = "Bearer $token" }

    try {
        if ($null -eq $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }

        $jsonBody = $Body | ConvertTo-Json -Depth 16
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -ContentType 'application/json' -Body $jsonBody
    }
    catch {
        $response = $_.Exception.Response
        if ($null -ne $response) {
            $statusCode = [int]$response.StatusCode
            if ($AllowStatusCodes -contains $statusCode) {
                return [pscustomobject]@{
                    StatusCode = $statusCode
                    Ignored    = $true
                }
            }
        }

        throw
    }
}

function Invoke-GraphSubscriptionReauthorize {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )

    $uri = "https://graph.microsoft.com/beta/subscriptions/$SubscriptionId/reauthorize"
    return (Invoke-GraphRequest -Method 'POST' -Uri $uri)
}

function Set-GraphSubscriptionExpiration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpirationDateTime
    )

    $uri = "https://graph.microsoft.com/v1.0/subscriptions/$SubscriptionId"
    $body = @{ expirationDateTime = $ExpirationDateTime }
    return (Invoke-GraphRequest -Method 'PATCH' -Uri $uri -Body $body)
}

Export-ModuleMember -Function @(
    'Get-Policy',
    'Get-DedupeKey',
    'Test-AndSetDedupe',
    'Get-ManagedIdentityAccessToken',
    'New-GovernanceWorkItem',
    'Get-GraphNotificationItems',
    'Test-IsGraphLifecycleEvent',
    'Invoke-GraphSubscriptionReauthorize',
    'Set-GraphSubscriptionExpiration'
)
