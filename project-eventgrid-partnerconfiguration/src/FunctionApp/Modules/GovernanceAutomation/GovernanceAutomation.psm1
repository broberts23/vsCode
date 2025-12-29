Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FunctionAppRootPath {
    <#
    .SYNOPSIS
    Returns the absolute path to the Function App root directory.

    .DESCRIPTION
    The module lives under `<FunctionAppRoot>/Modules/GovernanceAutomation`. This helper walks up two directories
    from `$PSScriptRoot` to find the Function App root. It is used to resolve relative paths like `policy/policy.json`.

    .OUTPUTS
    System.String

    .EXAMPLE
    Get-FunctionAppRootPath
    #>

    [CmdletBinding()]
    param()

    # Module lives at: <FunctionAppRoot>/Modules/GovernanceAutomation
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}

function Resolve-GovernancePath {
    <#
    .SYNOPSIS
    Resolves a relative governance path to an absolute file system path.

    .DESCRIPTION
    If the provided path is already rooted (absolute), it is returned unchanged.
    Otherwise the path is treated as relative to the Function App root (see `Get-FunctionAppRootPath`).

    .PARAMETER Path
    The path to resolve. Can be absolute or relative.

    .OUTPUTS
    System.String

    .EXAMPLE
    Resolve-GovernancePath -Path 'policy/policy.json'
    #>

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
    <#
    .SYNOPSIS
    Loads and parses the governance policy JSON file.

    .DESCRIPTION
    Resolves the provided policy path (absolute or relative to the Function App root), validates the file exists,
    then parses it as JSON.

    .PARAMETER PolicyPath
    Path to the policy JSON file. Supports absolute paths or paths relative to the Function App root.

    .OUTPUTS
    System.Object

    .EXAMPLE
    $policy = Get-Policy -PolicyPath 'policy/policy.json'
    #>

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
    <#
    .SYNOPSIS
    Builds a stable dedupe key for an Event Grid event.

    .DESCRIPTION
    Generates a string key that is stable across retries so the system can implement idempotency.
    Understands both EventGridSchema (`eventType`, `eventTime`, `topic`) and CloudEvents 1.0 (`type`, `time`, `source`).

    .PARAMETER Event
    The Event Grid event object. If an array is provided, it must contain exactly one item.

    .OUTPUTS
    System.String

    .EXAMPLE
    $key = Get-DedupeKey -Event $EventGridEvent
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Event')]
        [object]$InputEvent
    )

    # Defensive: the Event Grid trigger can hand us an array (batch). We expect a single event here.
    if ($InputEvent -is [System.Array]) {
        if ($InputEvent.Count -eq 1) {
            $InputEvent = $InputEvent[0]
        }
        else {
            throw "Get-DedupeKey expects a single event object; received an array of $($InputEvent.Count)."
        }
    }

    # Event Grid can deliver in either EventGridSchema or CloudEvents 1.0.
    # - EventGridSchema: eventType, eventTime, topic
    # - CloudEvents:     type, time, source
    $id = if ($InputEvent.PSObject.Properties.Name -contains 'id') { [string]$InputEvent.id } else { '' }
    $type = if ($InputEvent.PSObject.Properties.Name -contains 'eventType') { [string]$InputEvent.eventType } elseif ($InputEvent.PSObject.Properties.Name -contains 'type') { [string]$InputEvent.type } else { '' }
    $subject = if ($InputEvent.PSObject.Properties.Name -contains 'subject') { [string]$InputEvent.subject } else { '' }
    $time = if ($InputEvent.PSObject.Properties.Name -contains 'eventTime') { [string]$InputEvent.eventTime } elseif ($InputEvent.PSObject.Properties.Name -contains 'time') { [string]$InputEvent.time } else { '' }

    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = "$time-$subject-$type"
    }

    $dedupeKey = "$type|$subject|$id"

    # If we still couldn't extract anything meaningful, fall back to hashing the full payload
    # to avoid pathological collisions like "||--".
    $idLooksEmpty = ([string]::IsNullOrWhiteSpace($id) -or $id -eq '--' -or $id -eq '-')
    if ([string]::IsNullOrWhiteSpace($type) -and [string]::IsNullOrWhiteSpace($subject) -and $idLooksEmpty) {
        $json = $InputEvent | ConvertTo-Json -Depth 32 -Compress
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
    <#
    .SYNOPSIS
    Computes a SHA-256 hash of a string and returns it as lowercase hex.

    .DESCRIPTION
    Used to convert potentially-large keys into a fixed-length value (for example for Azure Table Storage
    PartitionKey/RowKey components).

    .PARAMETER Value
    The input string to hash. Empty strings are allowed.

    .OUTPUTS
    System.String

    .EXAMPLE
    ConvertTo-Sha256Hex -Value 'type|subject|id'
    #>

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
    <#
    .SYNOPSIS
    Gets an access token for a resource using the Function App's managed identity.

    .DESCRIPTION
    Uses the managed identity endpoint exposed by Azure Functions/App Service to request an OAuth 2.0 access token
    for the specified resource.

    Supports both the newer `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` variables and the older `MSI_ENDPOINT`/`MSI_SECRET`.
    If `MANAGED_IDENTITY_CLIENT_ID` is set, the request includes `client_id=...` to select a user-assigned identity.

    .PARAMETER Resource
    The resource/audience to request a token for.

    .OUTPUTS
    System.String

    .EXAMPLE
    $graphToken = Get-ManagedIdentityAccessToken
    #>

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
    <#
    .SYNOPSIS
    Builds a lightweight Table Storage context object from environment/config values.

    .DESCRIPTION
    Returns an object containing the storage account name and the resolved Table endpoint URI.
    This module uses REST calls authenticated with managed identity, so this context is just enough to build URIs.

    .PARAMETER StorageAccountName
    The Storage Account name.

    .PARAMETER EndpointSuffix
    Optional endpoint suffix (defaults to `core.windows.net`).

    .PARAMETER TableEndpoint
    Optional full Table endpoint URI.

    .OUTPUTS
    System.Object
    #>

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
    <#
    .SYNOPSIS
    Invokes an authenticated Azure Table Storage REST request using managed identity.

    .DESCRIPTION
    Builds a REST request to the Table endpoint and authenticates using a managed identity access token
    for the Storage resource (`https://storage.azure.com/`).

    .PARAMETER Method
    HTTP method to use. Supported values: GET, POST, PUT, MERGE, DELETE.

    .PARAMETER Path
    The Table REST path relative to the Table endpoint.

    .PARAMETER AllowStatusCodes
    Optional list of HTTP status codes that should be treated as handled.

    .OUTPUTS
    System.Object
    #>

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
    <#
    .SYNOPSIS
    Implements idempotency by recording a dedupe key in Azure Table Storage.

    .DESCRIPTION
    Hashes the provided dedupe key to build deterministic PartitionKey/RowKey values, then attempts to insert
    an entity into the specified table. If the entity already exists, Azure Table Storage returns HTTP 409 Conflict.

    .PARAMETER DedupeKey
    Stable dedupe key string (for example from `Get-DedupeKey`).

    .PARAMETER StorageAccountName
    The Storage Account name hosting the table.

    .PARAMETER TableName
    The table name.

    .OUTPUTS
    System.Boolean
    #>

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

function Test-DedupeExists {
    <#
    .SYNOPSIS
    Checks whether a dedupe key already exists in Azure Table Storage.

    .DESCRIPTION
    Uses the same SHA-256 hashing strategy as `Test-AndSetDedupe` to derive PartitionKey/RowKey, then performs
    a GET against the Table entity. Returns `$true` when the entity exists and `$false` when it does not.

    This is useful when you need a read-only existence check (for example, to skip work) without creating the
    dedupe record ahead of a potentially failing operation.

    .PARAMETER DedupeKey
    Stable dedupe key string.

    .PARAMETER StorageAccountName
    The Storage Account name hosting the table.

    .PARAMETER TableName
    The table name.

    .OUTPUTS
    System.Boolean
    #>

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

    # Escape single quotes for OData key syntax.
    $pk = $partitionKey.Replace("'", "''")
    $rk = $rowKey.Replace("'", "''")

    $path = "$TableName(PartitionKey='$pk',RowKey='$rk')"
    $result = Invoke-AzureStorageTableRequest -Method 'GET' -Path $path -StorageAccountName $StorageAccountName -EndpointSuffix $EndpointSuffix -TableEndpoint $TableEndpoint -AllowStatusCodes @(404)

    if ($null -ne $result -and $result.PSObject.Properties.Name -contains 'StatusCode' -and $result.StatusCode -eq 404) {
        return $false
    }

    return $true
}

function Get-DedupeEntity {
    <#
    .SYNOPSIS
    Gets an existing dedupe entity from Azure Table Storage.

    .DESCRIPTION
    Uses the same SHA-256 hashing strategy as `Test-AndSetDedupe` to derive PartitionKey/RowKey, then performs
    a GET against the Table entity.

    Returns the entity object when present and `$null` when not found.
    This enables TTL-style logic by inspecting properties like `DedupedAtUtc`.

    .PARAMETER DedupeKey
    Stable dedupe key string.

    .PARAMETER StorageAccountName
    The Storage Account name hosting the table.

    .PARAMETER TableName
    The table name.

    .OUTPUTS
    System.Object
    #>

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

    # Escape single quotes for OData key syntax.
    $pk = $partitionKey.Replace("'", "''")
    $rk = $rowKey.Replace("'", "''")

    $path = "$TableName(PartitionKey='$pk',RowKey='$rk')"
    $result = Invoke-AzureStorageTableRequest -Method 'GET' -Path $path -StorageAccountName $StorageAccountName -EndpointSuffix $EndpointSuffix -TableEndpoint $TableEndpoint -AllowStatusCodes @(404)

    if ($null -ne $result -and $result.PSObject.Properties.Name -contains 'StatusCode' -and $result.StatusCode -eq 404) {
        return $null
    }

    return $result
}

function New-GovernanceWorkItem {
    <#
    .SYNOPSIS
    Creates a normalized work-item object from an Event Grid event.

    .DESCRIPTION
    Takes an Event Grid event and a policy path and returns a stable work-item object that downstream queue
    workers can process.

    Normalizes EventGridSchema and CloudEvents 1.0 fields (`eventType/type`, `eventTime/time`, `topic/source`).
    Extracts key Microsoft Graph partner-event details from `data.*` when present and normalizes timestamps to ISO 8601 UTC.

    .PARAMETER EventGridEvent
    The Event Grid event object. If an array is provided, it must contain exactly one item.

    .PARAMETER PolicyPath
    Path to the policy JSON.

    .OUTPUTS
    System.Object
    #>

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
    <#
    .SYNOPSIS
    Extracts Microsoft Graph notification items from an Event Grid event payload.

    .DESCRIPTION
    Graph change notifications and lifecycle notifications are typically shaped like:
    `{ "value": [ { ... }, { ... } ] }`

    When delivered through Event Grid Partner Topics, the Graph payload is commonly nested under `EventGridEvent.data`.
    This function defensively probes multiple common wrappers and always returns an array (possibly empty).

    .PARAMETER EventGridEvent
    The Event Grid event object.

    .OUTPUTS
    System.Object[]
    #>

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
    <#
    .SYNOPSIS
    Determines whether an Event Grid event represents a Microsoft Graph lifecycle notification.

    .DESCRIPTION
    Uses `Get-GraphNotificationItems` and returns `$true` if any item contains a non-empty `lifecycleEvent` property.

    .PARAMETER EventGridEvent
    The Event Grid event object.

    .OUTPUTS
    System.Boolean
    #>

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
    <#
    .SYNOPSIS
    Invokes a Microsoft Graph REST request using managed identity.

    .DESCRIPTION
    Requests an access token for Microsoft Graph and performs an HTTP request with a Bearer token.
    Supports an allow-list of HTTP status codes so callers can treat certain responses as handled.

    .PARAMETER Method
    HTTP method to use.

    .PARAMETER Uri
    Absolute Microsoft Graph URI.

    .OUTPUTS
    System.Object
    #>

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
    <#
    .SYNOPSIS
    Calls Microsoft Graph to reauthorize a subscription.

    .DESCRIPTION
    Invokes the Graph subscription `reauthorize` action (beta endpoint). This is used when Graph sends a lifecycle
    notification indicating the subscription needs reauthorization.

    .PARAMETER SubscriptionId
    The Graph subscription id.

    .OUTPUTS
    System.Object
    #>

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
    <#
    .SYNOPSIS
    Renews a Microsoft Graph subscription by updating its expiration date.

    .DESCRIPTION
    Sends a PATCH to the Graph subscription with a new `expirationDateTime`.

    .PARAMETER SubscriptionId
    The Graph subscription id.

    .PARAMETER ExpirationDateTime
    The new expiration date/time as a string (ISO 8601).

    .OUTPUTS
    System.Object
    #>

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
    'Test-DedupeExists',
    'Get-DedupeEntity',
    'Get-ManagedIdentityAccessToken',
    'New-GovernanceWorkItem',
    'Get-GraphNotificationItems',
    'Test-IsGraphLifecycleEvent',
    'Invoke-GraphRequest',
    'Invoke-GraphSubscriptionReauthorize',
    'Set-GraphSubscriptionExpiration'
)
