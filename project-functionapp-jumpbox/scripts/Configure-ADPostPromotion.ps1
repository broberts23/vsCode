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

Import-Module ActiveDirectory
Import-Module DnsServer -ErrorAction SilentlyContinue

$timeoutSeconds = 300
$started = Get-Date
while ($true) {
    try {
        Get-ADDomain -Identity $DomainName -ErrorAction Stop | Out-Null
        break
    }
    catch {
        if (((Get-Date) - $started).TotalSeconds -ge $timeoutSeconds) {
            throw 'Timed out waiting for AD Web Services.'
        }

        Start-Sleep -Seconds 10
    }
}

if (Get-Command -Name Set-DnsServerForwarder -ErrorAction SilentlyContinue) {
    Set-DnsServerForwarder -IPAddress $DnsForwarders | Out-Null
}

$securePassword = ConvertTo-SecureString -String $ServiceAccountPassword -AsPlainText -Force
$existingUser = Get-ADUser -Filter "SamAccountName -eq '$ServiceAccountName'" -ErrorAction SilentlyContinue

if (-not $existingUser -and $PSCmdlet.ShouldProcess($ServiceAccountName, 'Create remoting service account')) {
    $newUserParameters = @{
        Name = $ServiceAccountName
        SamAccountName = $ServiceAccountName
        UserPrincipalName = "$ServiceAccountName@$DomainName"
        AccountPassword = $securePassword
        Enabled = $true
        PasswordNeverExpires = $true
    }
    New-ADUser @newUserParameters
}