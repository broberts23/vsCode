#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    [Parameter()]
    [string]$Description,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Resources
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot/Utcm.Common.ps1"

New-UtcmSnapshotJob -DisplayName $DisplayName -Description $Description -Resources $Resources
