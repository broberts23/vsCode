#!/usr/bin/env powershell
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainNetBiosName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SafeModeAdminPasswordBase64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$plainPassword = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SafeModeAdminPasswordBase64))
$safeModePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

if ($PSCmdlet.ShouldProcess($DomainName, 'Promote server to domain controller')) {
    $addsParameters = @{
        DomainName = $DomainName
        DomainNetbiosName = $DomainNetBiosName
        SafeModeAdministratorPassword = $safeModePassword
        InstallDns = $true
        CreateDnsDelegation = $false
        NoRebootOnCompletion = $false
        Force = $true
    }
    Install-ADDSForest @addsParameters
}