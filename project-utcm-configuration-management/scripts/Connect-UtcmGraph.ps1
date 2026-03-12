#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Interactive')]
    [switch]$Interactive,

    [Parameter(Mandatory, ParameterSetName = 'DeviceCode')]
    [switch]$DeviceCode,

    [Parameter(Mandatory, ParameterSetName = 'AppOnlyCert')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'AppOnlyCert')]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = 'AppOnlyCert')]
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'ManagedIdentity')]
    [switch]$ManagedIdentity
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# UTCM APIs are in /beta, but auth is still via the normal Graph token.
# Keep scopes minimal; add more only if needed.
$defaultScopes = @(
    'ConfigurationMonitoring.ReadWrite.All'
)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Missing Microsoft Graph PowerShell SDK. Install it: https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0'
}

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

switch ($PSCmdlet.ParameterSetName) {
    'Interactive' {
        Connect-MgGraph -Scopes $defaultScopes -ContextScope Process -NoWelcome
        break
    }
    'DeviceCode' {
        Connect-MgGraph -Scopes $defaultScopes -UseDeviceCode -ContextScope Process -NoWelcome
        break
    }
    'AppOnlyCert' {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ContextScope Process -NoWelcome
        break
    }
    'ManagedIdentity' {
        Connect-MgGraph -Identity -ContextScope Process -NoWelcome
        break
    }
}

Get-MgContext
