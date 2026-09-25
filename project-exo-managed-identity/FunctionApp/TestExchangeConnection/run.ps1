using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ExchangeOnlineConnection -Force

try {
    $connectionStatus = Assert-ExchangeOnlineConnection

    # Read outside the SemaphoreSlim so the gate only covers connect/refresh.
    $domains = @(Get-AcceptedDomain | Select-Object -Property DomainName, DomainType, Default)

    $body = [ordered]@{
        status            = 'ok'
        connectionAction  = $connectionStatus.Action
        connectionId      = $connectionStatus.ConnectionId
        tokenStatus       = $connectionStatus.TokenStatus
        organization      = $connectionStatus.Organization
        acceptedDomains   = $domains
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
        timestampUtc      = [datetime]::UtcNow.ToString('o')
    }

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $body
            Headers    = @{ 'Content-Type' = 'application/json' }
        })
}
catch {
    Write-Error $_
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body       = @{
                status  = 'error'
                message = $_.Exception.Message
            }
            Headers    = @{ 'Content-Type' = 'application/json' }
        })
}
