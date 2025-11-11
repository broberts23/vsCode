#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
<#
.SYNOPSIS
Helper to ensure Microsoft.Graph.Beta module is available and connected.
#>
Function Invoke-WiEnsureGraphBeta {
    [CmdletBinding()] Param()
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Beta)) {
        Throw 'Microsoft.Graph.Beta module not found. Install it to use beta risky workload identity APIs. See https://learn.microsoft.com/powershell/microsoftgraph/overview?view=graph-powershell-beta'
    }
    if (-not (Get-Module -Name Microsoft.Graph.Beta)) {
        Import-Module Microsoft.Graph.Beta -ErrorAction Stop
    }
}

Function Invoke-WiPaged {
    [CmdletBinding()] Param(
        [Parameter(Mandatory)][scriptblock]$Script,
        [Parameter()][hashtable]$Parameters
    )
    $result = @()
    $page = & $Script @Parameters
    $result += $page
    while ($null -ne $page.NextLink) {
        $Parameters = @{}
        $Parameters['-PageSize'] = 999
        $page = Invoke-RestMethod -Method Get -Uri $page.NextLink -Headers @{ Authorization = "Bearer $((Get-MgContext).AccessToken)" }
        $result += $page.value
    }
    return $result
}
