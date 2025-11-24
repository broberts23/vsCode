#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Pester tests for ResetUserPassword function
.DESCRIPTION
    Integration tests for the HTTP trigger function
.LINK
    https://pester.dev
#>

BeforeAll {
    # Determine project root from test file location
    # When running via Pester configuration, use PWD (project root)
    # When running directly, use calculated path from script location
    if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
        $script:TestProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    }
    else {
        # Fallback to PWD when PSScriptRoot is not available (Pester config execution)
        $script:TestProjectRoot = Get-Location | Select-Object -ExpandProperty Path
    }
    
    Write-Host "ProjectRoot set to: $script:TestProjectRoot" -ForegroundColor Cyan
    
    # Import required modules
    $modulePath = Join-Path $script:TestProjectRoot 'Modules/PasswordResetHelpers/PasswordResetHelpers.psm1'
    Write-Host "Loading module from: $modulePath" -ForegroundColor Cyan
    Import-Module $modulePath -Force
    
    # Mock environment variables
    $env:REQUIRED_ROLE = 'Role.PasswordReset'
    
    # Helper to create client principal header
    function New-ClientPrincipalHeader {
        param(
            [string[]]$Roles = @()
        )
        
        $claims = @()
        foreach ($role in $Roles) {
            $claims += @{ typ = 'roles'; val = $role }
        }
        
        $principal = @{
            auth_typ = 'aad'
            claims   = $claims
        }
        
        $json = $principal | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        return [System.Convert]::ToBase64String($bytes)
    }
}

Describe 'ResetUserPassword Function' {
    
    Context 'Request Validation' {
        BeforeEach {
            # Set project root for path resolution in tests
            $script:TestProjectRoot = Get-Location | Select-Object -ExpandProperty Path
            
            # Mock the helper functions
            Mock Test-JwtToken { } -ModuleName PasswordResetHelpers
            Mock Test-RoleClaim { $true } -ModuleName PasswordResetHelpers
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            # Simulate function execution
            $script:response = $null
            
            function Push-OutputBinding {
                param($Name, $Value)
                $script:response = $Value
            }
        }
        
        It 'Should reject request without X-MS-CLIENT-PRINCIPAL header' {
            $Request = @{
                Headers = @{}
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            # Execute function script
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 401
            ($script:response.Body | ConvertFrom-Json).error | Should -Be 'Unauthorized'
        }
        
        It 'Should reject request with invalid X-MS-CLIENT-PRINCIPAL header' {
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = 'not-valid-base64!!!' }
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 401
        }
        
        It 'Should reject request without samAccountName in body' {
            $clientPrincipalHeader = New-ClientPrincipalHeader -Roles @('Role.PasswordReset')
            
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = $clientPrincipalHeader }
                Body    = @{} | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 400
            ($script:response.Body | ConvertFrom-Json).message | Should -Match 'samAccountName'
        }
    }
    
    Context 'Client Principal Validation' {
        BeforeEach {
            # Set project root for path resolution in tests
            $script:TestProjectRoot = Get-Location | Select-Object -ExpandProperty Path
            
            Mock Test-RoleClaim { $true } -ModuleName PasswordResetHelpers
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            $script:response = $null
            
            function Push-OutputBinding {
                param($Name, $Value)
                $script:response = $Value
            }
        }
        
        It 'Should reject invalid client principal' {
            Mock Get-ClientPrincipal { throw 'Failed to decode client principal' } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = 'invalid-header' }
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 401
        }
    }
    
    Context 'Role Authorization' {
        BeforeEach {
            # Set project root for path resolution in tests
            $script:TestProjectRoot = Get-Location | Select-Object -ExpandProperty Path
            
            Mock Get-ClientPrincipal {
                [PSCustomObject]@{
                    auth_typ = 'aad'
                    claims   = @()
                }
            } -ModuleName PasswordResetHelpers
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            $script:response = $null
            
            function Push-OutputBinding {
                param($Name, $Value)
                $script:response = $Value
            }
        }
        
        It 'Should reject requests without required role' {
            Mock Test-RoleClaim { $false } -ModuleName PasswordResetHelpers
            
            $clientPrincipalHeader = New-ClientPrincipalHeader -Roles @()
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = $clientPrincipalHeader }
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 403
            ($script:response.Body | ConvertFrom-Json).error | Should -Be 'Forbidden'
        }
        
        It 'Should accept requests with required role' {
            Mock Test-RoleClaim { $true } -ModuleName PasswordResetHelpers
            
            $global:ADServiceCredential = [PSCredential]::new('CONTOSO\svc-test', (ConvertTo-SecureString 'test' -AsPlainText -Force))
            $clientPrincipalHeader = New-ClientPrincipalHeader -Roles @('Role.PasswordReset')
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = $clientPrincipalHeader }
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 200
        }
    }
    
    Context 'Password Reset Operations' {
        BeforeEach {
            # Set project root for path resolution in tests
            $script:TestProjectRoot = Get-Location | Select-Object -ExpandProperty Path
            
            Mock Get-ClientPrincipal {
                [PSCustomObject]@{
                    auth_typ = 'aad'
                    claims   = @(
                        @{ typ = 'roles'; val = 'Role.PasswordReset' }
                    )
                }
            } -ModuleName PasswordResetHelpers
            Mock Test-RoleClaim { $true } -ModuleName PasswordResetHelpers
            
            $global:ADServiceCredential = [PSCredential]::new('CONTOSO\svc-test', (ConvertTo-SecureString 'test' -AsPlainText -Force))
            
            $script:response = $null
            
            function Push-OutputBinding {
                param($Name, $Value)
                $script:response = $Value
            }
        }
        
        It 'Should return generated password on successful reset' {
            Mock New-SecurePassword { 'GeneratedPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            $clientPrincipalHeader = New-ClientPrincipalHeader -Roles @('Role.PasswordReset')
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = $clientPrincipalHeader }
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 200
            $responseBody = $script:response.Body | ConvertFrom-Json
            $responseBody.password | Should -Be 'GeneratedPassword123!'
            $responseBody.samAccountName | Should -Be 'jdoe'
        }
        
        It 'Should handle user not found error' {
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { throw 'Cannot find an object' } -ModuleName PasswordResetHelpers
            
            $clientPrincipalHeader = New-ClientPrincipalHeader -Roles @('Role.PasswordReset')
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = $clientPrincipalHeader }
                Body    = @{ samAccountName = 'nonexistent' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 500
        }
        
        It 'Should include security headers in response' {
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            $clientPrincipalHeader = New-ClientPrincipalHeader -Roles @('Role.PasswordReset')
            $Request = @{
                Headers = @{ 'X-MS-CLIENT-PRINCIPAL' = $clientPrincipalHeader }
                Body    = @{ samAccountName = 'jdoe' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.Headers.'Cache-Control' | Should -Match 'no-store'
            $script:response.Headers.'X-Content-Type-Options' | Should -Be 'nosniff'
            $script:response.Headers.'Strict-Transport-Security' | Should -Match 'max-age'
        }
    }
}
