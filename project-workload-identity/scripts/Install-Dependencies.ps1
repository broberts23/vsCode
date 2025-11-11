#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
<#!
.SYNOPSIS
Install required PowerShell modules for the toolkit.
#!>
[CmdletBinding()] Param()

Function Install-IfMissing {
    Param([string]$Name,[string]$Version)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Information "Installing $Name $Version" -InformationAction Continue
        Install-Module -Name $Name -RequiredVersion $Version -Scope CurrentUser -Force -AllowClobber
    } else {
        Write-Information "$Name already present" -InformationAction Continue
    }
}

Install-IfMissing -Name Microsoft.Graph -Version '2.14.0'
# Optional beta modules could be added similarly with preview notice.
Write-Information 'Module installation complete.' -InformationAction Continue
