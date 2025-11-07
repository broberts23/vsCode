#!/usr/bin/env pwsh
Requires -Version 7.4
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module Pester -ErrorAction Stop

Describe 'SmokeTests Module Placeholder' {
    Context 'Function presence' {
        It 'Has Invoke-EphemeralSmokeTests function' {
            . "$PSScriptRoot/../scripts/SmokeTests.ps1"
            (Get-Command Invoke-EphemeralSmokeTests -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        }
    }
}
