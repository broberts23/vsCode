#Requires -Version 7.4

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Process-wide gate shared across runspaces. A script-scoped SemaphoreSlim would
# not serialize Connect-ExchangeOnline when PSWorkerInProcConcurrencyUpperBound > 1.
if (-not ('ExoConnectionGate' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Threading;
public static class ExoConnectionGate
{
    public static readonly SemaphoreSlim Instance = new SemaphoreSlim(1, 1);
}
'@
}

function Get-ExoOrganization {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $organization = $env:EXCHANGE_ORGANIZATION
    if ([string]::IsNullOrWhiteSpace($organization)) {
        throw 'App setting EXCHANGE_ORGANIZATION is required (tenant *.onmicrosoft.com domain).'
    }

    return $organization.Trim()
}

function Test-ExoConnectionHealthy {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($connections.Count -eq 0) {
        return $false
    }

    foreach ($connection in $connections) {
        if ($connection.TokenStatus -eq 'Active') {
            return $true
        }
    }

    return $false
}

function Connect-ExoManagedIdentity {
    [CmdletBinding()]
    param()

    $organization = Get-ExoOrganization
    Write-Information "Connecting to Exchange Online with managed identity for $organization"

    $connectParams = @{
        ManagedIdentity = $true
        Organization    = $organization
        ShowBanner      = $false
        CommandName     = @('Get-AcceptedDomain', 'Get-ConnectionInformation', 'Disconnect-ExchangeOnline')
    }

    Connect-ExchangeOnline @connectParams
}

function Initialize-ExchangeOnlineConnection {
    <#
    .SYNOPSIS
        Opens the Exchange Online managed-identity session for the current runspace.
    .DESCRIPTION
        Intended for profile.ps1. Serializes Connect-ExchangeOnline behind the
        process-wide SemaphoreSlim so concurrent runspace cold starts do not race.
    #>
    [CmdletBinding()]
    param()

    $gate = [ExoConnectionGate]::Instance
    $gate.Wait()
    try {
        if (Test-ExoConnectionHealthy) {
            Write-Information 'Exchange Online connection already active; skipping profile connect.'
            return
        }

        Connect-ExoManagedIdentity
        Write-Information 'Exchange Online managed-identity connection established in profile.'
    }
    catch {
        Write-Error "Failed to initialize Exchange Online connection: $_"
        throw
    }
    finally {
        $null = $gate.Release()
    }
}

function Assert-ExchangeOnlineConnection {
    <#
    .SYNOPSIS
        Ensures an active Exchange Online connection before a cmdlet runs.
    .DESCRIPTION
        Waits on the process-wide SemaphoreSlim, inspects Get-ConnectionInformation,
        and reconnects only when the session is missing or TokenStatus is not Active.
        Releases the gate before returning so the caller can run reads outside the lock.
    .OUTPUTS
        PSCustomObject with Action (Reused|Refreshed) and Connection metadata.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $gate = [ExoConnectionGate]::Instance
    $gate.Wait()
    try {
        if (Test-ExoConnectionHealthy) {
            $connection = @(Get-ConnectionInformation)[0]
            Write-Information 'Exchange Online connection reused (TokenStatus Active).'
            return [pscustomobject]@{
                Action         = 'Reused'
                ConnectionId   = $connection.ConnectionId
                TokenStatus    = [string]$connection.TokenStatus
                Organization   = $connection.Organization
                State          = [string]$connection.State
            }
        }

        Write-Information 'Exchange Online connection missing or expired; refreshing.'
        Connect-ExoManagedIdentity

        $connection = @(Get-ConnectionInformation)[0]
        if (-not (Test-ExoConnectionHealthy)) {
            throw 'Connect-ExchangeOnline completed but no Active TokenStatus was reported.'
        }

        return [pscustomobject]@{
            Action         = 'Refreshed'
            ConnectionId   = $connection.ConnectionId
            TokenStatus    = [string]$connection.TokenStatus
            Organization   = $connection.Organization
            State          = [string]$connection.State
        }
    }
    catch {
        Write-Error "Failed to assert Exchange Online connection: $_"
        throw
    }
    finally {
        $null = $gate.Release()
    }
}

Export-ModuleMember -Function @(
    'Initialize-ExchangeOnlineConnection'
    'Assert-ExchangeOnlineConnection'
)
