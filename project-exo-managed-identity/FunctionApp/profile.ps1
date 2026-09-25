#Requires -Version 7.4

<#
.SYNOPSIS
    PowerShell profile for Azure Function App initialization.
.DESCRIPTION
    Runs once per PowerShell runspace on cold start. Opens the Exchange Online
    managed-identity connection for this runspace via the helper module.
.LINK
    https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell#powershell-profile
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ExchangeOnlineConnection -Force

if ($env:MSI_ENDPOINT -and $env:MSI_SECRET) {
    Initialize-ExchangeOnlineConnection
} else {
    throw 'Managed identity is not available. Please configure the function app to use a managed identity.'
}
