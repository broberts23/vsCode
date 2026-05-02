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

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
if ($computerSystem.PartOfDomain -and $computerSystem.Domain -eq $DomainName) {
    Write-Information "Machine is already joined to $DomainName." -InformationAction Continue
    return
}

if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
    $upAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($adapter in $upAdapters) {
        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DnsServer
    }
}

$securePassword = ConvertTo-SecureString -String $DomainJoinPassword -AsPlainText -Force
$credential = [pscredential]::new($DomainJoinUsername, $securePassword)

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Join domain and reboot')) {
    Add-Computer -DomainName $DomainName -Credential $credential -Restart -Force
}