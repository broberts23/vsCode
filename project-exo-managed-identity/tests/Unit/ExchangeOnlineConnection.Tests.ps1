#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Pester tests for ExchangeOnlineConnection module.
.DESCRIPTION
    Unit tests for session reuse, refresh, and SemaphoreSlim release on failure.
.LINK
    https://pester.dev
#>

BeforeAll {
    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $modulePath = Join-Path $projectRoot 'FunctionApp/Modules/ExchangeOnlineConnection/ExchangeOnlineConnection.psm1'

    # Global stubs so Mock -ModuleName can resolve Exchange Online cmdlets.
    function global:Get-ConnectionInformation {
        param()
        throw 'Get-ConnectionInformation stub invoked without a Mock'
    }

    function global:Connect-ExchangeOnline {
        param()
        throw 'Connect-ExchangeOnline stub invoked without a Mock'
    }

    Import-Module $modulePath -Force

    $env:EXCHANGE_ORGANIZATION = 'contoso.onmicrosoft.com'
}

AfterAll {
    Remove-Item -Path Function:\global:Get-ConnectionInformation -ErrorAction SilentlyContinue
    Remove-Item -Path Function:\global:Connect-ExchangeOnline -ErrorAction SilentlyContinue
}

Describe 'ExchangeOnlineConnection Module' {

    Context 'Module load' {
        It 'Loads the module successfully' {
            Get-Module ExchangeOnlineConnection | Should -Not -BeNullOrEmpty
        }

        It 'Exports Initialize-ExchangeOnlineConnection' {
            Get-Command Initialize-ExchangeOnlineConnection -Module ExchangeOnlineConnection |
                Should -Not -BeNullOrEmpty
        }

        It 'Exports Assert-ExchangeOnlineConnection' {
            Get-Command Assert-ExchangeOnlineConnection -Module ExchangeOnlineConnection |
                Should -Not -BeNullOrEmpty
        }

        It 'Defines the process-wide ExoConnectionGate type' {
            'ExoConnectionGate' -as [type] | Should -Not -BeNullOrEmpty
            [ExoConnectionGate]::Instance | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Assert-ExchangeOnlineConnection' {
        BeforeEach {
            # Drain any leftover wait from a prior failed test.
            while ([ExoConnectionGate]::Instance.CurrentCount -lt 1) {
                $null = [ExoConnectionGate]::Instance.Release()
            }
        }

        It 'Reuses a healthy Active session without calling Connect-ExchangeOnline' {
            Mock -ModuleName ExchangeOnlineConnection Get-ConnectionInformation {
                [pscustomobject]@{
                    ConnectionId = 'reuse-guid'
                    TokenStatus  = 'Active'
                    Organization = 'contoso.onmicrosoft.com'
                    State        = 'Connected'
                }
            }

            Mock -ModuleName ExchangeOnlineConnection Connect-ExchangeOnline { }

            $result = Assert-ExchangeOnlineConnection

            $result.Action | Should -Be 'Reused'
            $result.ConnectionId | Should -Be 'reuse-guid'
            $result.TokenStatus | Should -Be 'Active'
            Should -Invoke -ModuleName ExchangeOnlineConnection -CommandName Connect-ExchangeOnline -Times 0 -Exactly
        }

        It 'Reconnects once when no connection information exists' {
            $script:connectCalls = 0
            $script:infoCalls = 0

            Mock -ModuleName ExchangeOnlineConnection Get-ConnectionInformation {
                $script:infoCalls++
                if ($script:connectCalls -eq 0) {
                    return @()
                }

                return [pscustomobject]@{
                    ConnectionId = 'fresh-guid'
                    TokenStatus  = 'Active'
                    Organization = 'contoso.onmicrosoft.com'
                    State        = 'Connected'
                }
            }

            Mock -ModuleName ExchangeOnlineConnection Connect-ExchangeOnline {
                $script:connectCalls++
            }

            $result = Assert-ExchangeOnlineConnection

            $result.Action | Should -Be 'Refreshed'
            $result.ConnectionId | Should -Be 'fresh-guid'
            Should -Invoke -ModuleName ExchangeOnlineConnection -CommandName Connect-ExchangeOnline -Times 1 -Exactly
        }

        It 'Reconnects once when TokenStatus is not Active' {
            $script:connectCalls = 0

            Mock -ModuleName ExchangeOnlineConnection Get-ConnectionInformation {
                if ($script:connectCalls -eq 0) {
                    return [pscustomobject]@{
                        ConnectionId = 'stale-guid'
                        TokenStatus  = 'Expired'
                        Organization = 'contoso.onmicrosoft.com'
                        State        = 'Connected'
                    }
                }

                return [pscustomobject]@{
                    ConnectionId = 'refreshed-guid'
                    TokenStatus  = 'Active'
                    Organization = 'contoso.onmicrosoft.com'
                    State        = 'Connected'
                }
            }

            Mock -ModuleName ExchangeOnlineConnection Connect-ExchangeOnline {
                $script:connectCalls++
            }

            $result = Assert-ExchangeOnlineConnection

            $result.Action | Should -Be 'Refreshed'
            $result.ConnectionId | Should -Be 'refreshed-guid'
            Should -Invoke -ModuleName ExchangeOnlineConnection -CommandName Connect-ExchangeOnline -Times 1 -Exactly
        }

        It 'Releases the SemaphoreSlim when Connect-ExchangeOnline throws' {
            Mock -ModuleName ExchangeOnlineConnection Get-ConnectionInformation {
                return @()
            }

            Mock -ModuleName ExchangeOnlineConnection Connect-ExchangeOnline {
                throw 'simulated connect failure'
            }

            { Assert-ExchangeOnlineConnection } | Should -Throw -ExpectedMessage '*simulated connect failure*'

            [ExoConnectionGate]::Instance.CurrentCount | Should -Be 1

            # A subsequent healthy call must be able to acquire the gate again.
            Mock -ModuleName ExchangeOnlineConnection Get-ConnectionInformation {
                [pscustomobject]@{
                    ConnectionId = 'after-failure'
                    TokenStatus  = 'Active'
                    Organization = 'contoso.onmicrosoft.com'
                    State        = 'Connected'
                }
            }

            Mock -ModuleName ExchangeOnlineConnection Connect-ExchangeOnline { }

            $result = Assert-ExchangeOnlineConnection
            $result.Action | Should -Be 'Reused'
        }

        It 'Throws when EXCHANGE_ORGANIZATION is missing during refresh' {
            Mock -ModuleName ExchangeOnlineConnection Get-ConnectionInformation {
                return @()
            }

            $previous = $env:EXCHANGE_ORGANIZATION
            try {
                Remove-Item -Path Env:EXCHANGE_ORGANIZATION -ErrorAction SilentlyContinue
                { Assert-ExchangeOnlineConnection } | Should -Throw -ExpectedMessage '*EXCHANGE_ORGANIZATION*'
            }
            finally {
                $env:EXCHANGE_ORGANIZATION = $previous
            }

            [ExoConnectionGate]::Instance.CurrentCount | Should -Be 1
        }
    }
}
