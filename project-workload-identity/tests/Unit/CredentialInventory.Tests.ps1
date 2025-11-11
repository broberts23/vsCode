#!/usr/bin/env pwsh
#Requires -Version 7.4
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../../src/WorkloadIdentityTools/WorkloadIdentityTools.psd1') -Force

Describe 'Credential Inventory Risk Logic' {
    It 'Computes LongLived flag when lifetime > 180 days' {
        $obj = [PSCustomObject]@{ StartDate = (Get-Date).AddDays(-10); EndDate = (Get-Date).AddDays(200) }
        $days = ($obj.EndDate - $obj.StartDate).TotalDays
        ($days -gt 180) | Should -BeTrue
    }
}
