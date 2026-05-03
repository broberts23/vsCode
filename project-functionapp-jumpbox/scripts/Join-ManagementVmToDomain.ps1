#!/usr/bin/env powershell
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainJoinUsername,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainJoinPassword,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DnsServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogDirectory = 'C:\temp'
$script:LogFile = Join-Path $script:LogDirectory ("Join-ManagementVmToDomain-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (-not (Test-Path $script:LogDirectory)) {
    New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = '(no message)'
    }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:LogFile -Value "[$timestamp] $Message"
}

Write-Log "Starting management VM domain join workflow for domain '$DomainName'."
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName) {
        Write-Log "Machine is already joined to $DomainName."
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
        Write-Log "Configuring DNS server '$DnsServer' on active adapters before domain join."
        $dnsTargets = @(Get-NetIPConfiguration | Where-Object {
                $_.NetAdapter.Status -eq 'Up' -and
                ($_.IPv4Address -or $_.IPv6Address)
            })

        if ($dnsTargets.Count -eq 0) {
            throw 'No active IP-enabled network adapters were found for DNS configuration.'
        }

        foreach ($target in $dnsTargets) {
            $interfaceAlias = $target.InterfaceAlias
            if ([string]::IsNullOrWhiteSpace($interfaceAlias)) {
                continue
            }

            Set-DnsClientServerAddress -InterfaceAlias $interfaceAlias -ServerAddresses $DnsServer -ErrorAction Stop
            Write-Log "Updated DNS servers on adapter '$interfaceAlias' to '$DnsServer'."
        }

        try {
            Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Server $DnsServer -Type SRV -ErrorAction Stop | Out-Null
            Write-Log "Verified domain controller SRV records for '$DomainName' via DNS server '$DnsServer'."
        }
        catch {
            throw "DNS validation failed for domain '$DomainName' using server '$DnsServer': $($_.Exception.Message)"
        }
    }

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Join domain and reboot')) {
        $workerScriptPath = Join-Path $script:LogDirectory 'Complete-DomainJoin.ps1'
        $workerLogPath = Join-Path $script:LogDirectory 'Complete-DomainJoin.log'
        $workerTranscriptPath = Join-Path $script:LogDirectory ("Complete-DomainJoin-Transcript-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        $escapedDomainName = $DomainName.Replace("'", "''")
        $escapedUsername = $DomainJoinUsername.Replace("'", "''")
        $escapedPassword = $DomainJoinPassword.Replace("'", "''")

        $workerScript = @"
`$ErrorActionPreference = 'Stop'
function Write-WorkerLog {
    param([string]`$Message, [string]`$Level = 'Information')
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path '$workerLogPath' -Value "[`$timestamp] [`$Level] `$Message"
}
Start-Transcript -Path '$workerTranscriptPath' -Force | Out-Null
Write-WorkerLog 'Detached domain join worker started.'
`$securePassword = ConvertTo-SecureString -String '$escapedPassword' -AsPlainText -Force
`$credential = [pscredential]::new('$escapedUsername', `$securePassword)
try {
    Write-WorkerLog "Invoking Add-Computer for domain $escapedDomainName."
    Add-Computer -DomainName '$escapedDomainName' -Credential `$credential -Restart -Force
}
catch {
    Write-WorkerLog (`$_.Exception.Message) 'Error'
    Write-WorkerLog ((`$_ | Out-String).Trim()) 'Error'
    throw
}
finally {
    Stop-Transcript | Out-Null
}
"@

        Set-Content -Path $workerScriptPath -Value $workerScript -Encoding ASCII -Force
        Write-Log "Launching detached domain join worker '$workerScriptPath'."

        Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @(
            '-NoLogo'
            '-NoProfile'
            '-ExecutionPolicy', 'Bypass'
            '-File', $workerScriptPath
        ) -WindowStyle Hidden

        Write-Log "Domain join worker launched successfully. Worker log: $workerLogPath"
        Write-Log "Worker transcript path: $workerTranscriptPath"
        Write-Log 'The VM will reboot after the join completes.'
    }
}
catch {
    Write-Log "Join-ManagementVmToDomain failed: $($_.Exception.Message)"
    Write-Log ($_.ScriptStackTrace)
    throw
}