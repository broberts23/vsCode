#!/usr/bin/env powershell
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountName = 'svc-legacyjump',

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountPassword,

    [Parameter()]
    [string[]]$DnsForwarders = @('168.63.129.16')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogDirectory = 'C:\temp'
$script:LogFile = Join-Path $script:LogDirectory ("Configure-ADPostPromotion-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (-not (Test-Path $script:LogDirectory)) {
    New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = '(no message)'
    }

    Add-Content -Path $script:LogFile -Value "[$timestamp] [$Level] $Message"
}

Write-Log "Starting AD post-promotion configuration for domain '$DomainName'."
Import-Module ActiveDirectory
Import-Module DnsServer -ErrorAction SilentlyContinue

$timeoutSeconds = 300
$started = Get-Date
while ($true) {
    try {
        Get-ADDomain -Identity $DomainName -ErrorAction Stop | Out-Null
        Write-Log 'Active Directory Web Services is responding.'
        break
    }
    catch {
        if (((Get-Date) - $started).TotalSeconds -ge $timeoutSeconds) {
            Write-Log 'Timed out waiting for AD Web Services.' -Level Error
            throw 'Timed out waiting for AD Web Services.'
        }

        Write-Log 'Waiting for AD Web Services to become available...'
        Start-Sleep -Seconds 10
    }
}

if (Get-Command -Name Set-DnsServerForwarder -ErrorAction SilentlyContinue) {
    Write-Log ("Setting DNS forwarders to: {0}" -f ($DnsForwarders -join ', '))
    Set-DnsServerForwarder -IPAddress $DnsForwarders | Out-Null
}
else {
    Write-Log 'DnsServer module is unavailable; skipping DNS forwarder configuration.' -Level Warning
}

$securePassword = ConvertTo-SecureString -String $ServiceAccountPassword -AsPlainText -Force
$existingUser = Get-ADUser -Filter "SamAccountName -eq '$ServiceAccountName'" -ErrorAction SilentlyContinue

if (-not $existingUser -and $PSCmdlet.ShouldProcess($ServiceAccountName, 'Create remoting service account')) {
    $newUserParameters = @{
        Name                 = $ServiceAccountName
        SamAccountName       = $ServiceAccountName
        UserPrincipalName    = "$ServiceAccountName@$DomainName"
        AccountPassword      = $securePassword
        Enabled              = $true
        PasswordNeverExpires = $true
    }
    New-ADUser @newUserParameters
    Write-Log "Created remoting service account '$ServiceAccountName'."
}
else {
    Write-Log "Remoting service account '$ServiceAccountName' already exists; reconciling password and account settings."

    if ($PSCmdlet.ShouldProcess($ServiceAccountName, 'Reset remoting service account password')) {
        Set-ADAccountPassword -Identity $ServiceAccountName -Reset -NewPassword $securePassword -ErrorAction Stop
        Set-ADUser -Identity $ServiceAccountName -Enabled $true -PasswordNeverExpires $true -ErrorAction Stop
        Write-Log "Reset password and refreshed account settings for remoting service account '$ServiceAccountName'."
    }
}

Write-Log "Ensuring remoting service account '$ServiceAccountName' is a member of 'Domain Admins'."
$domainAdminsGroup = Get-ADGroup -Identity 'Domain Admins' -ErrorAction Stop
$serviceAccountGroups = Get-ADPrincipalGroupMembership -Identity $ServiceAccountName | Select-Object -ExpandProperty DistinguishedName
if ($serviceAccountGroups -contains $domainAdminsGroup.DistinguishedName) {
    Write-Log "Remoting service account '$ServiceAccountName' is already a member of 'Domain Admins'."
}
elseif ($PSCmdlet.ShouldProcess($ServiceAccountName, "Add to 'Domain Admins'")) {
    Add-ADGroupMember -Identity $domainAdminsGroup -Members $ServiceAccountName -ErrorAction Stop
    Write-Log "Added remoting service account '$ServiceAccountName' to 'Domain Admins'."
}

Write-Log "AD post-promotion configuration completed. Log file: $($script:LogFile)"