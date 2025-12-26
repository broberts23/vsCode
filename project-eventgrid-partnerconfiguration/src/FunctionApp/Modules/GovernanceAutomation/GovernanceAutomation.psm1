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

    $id = $Event.id
    $eventType = $Event.eventType
    $subject = $Event.subject

    if ([string]::IsNullOrWhiteSpace($id)) {
        $id = "$($Event.eventTime)-$subject-$eventType"
    }

    return "$eventType|$subject|$id"
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
            id        = $EventGridEvent.id
            eventType = $EventGridEvent.eventType
            subject   = $EventGridEvent.subject
            eventTime = $EventGridEvent.eventTime
            topic     = $EventGridEvent.topic
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

    # Graph change notifications (and lifecycle notifications) are typically shaped like:
    #   { "value": [ { ... }, { ... } ] }
    # When delivered through Event Grid Partner Topics, that payload is commonly in EventGridEvent.data
    # but we defensively probe a couple of common wrappers.
    $candidates = @(
        $EventGridEvent.data,
        $EventGridEvent.data.data,
        $EventGridEvent.payload,
        $EventGridEvent.payload.data
    )

    foreach ($candidate in $candidates) {
        if ($null -eq $candidate) {
            continue
        }

        if ($candidate.PSObject.Properties.Name -contains 'value') {
            $items = @($candidate.value)
            if ($items.Count -gt 0) {
                return $items
            }
        }
    }

    return @()
}

function Test-IsGraphLifecycleEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$EventGridEvent
    )

    $items = Get-GraphNotificationItems -EventGridEvent $EventGridEvent
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
