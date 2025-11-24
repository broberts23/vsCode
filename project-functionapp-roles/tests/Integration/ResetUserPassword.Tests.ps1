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
    $env:TENANT_ID = 'test-tenant-id'
    $env:EXPECTED_AUDIENCE = 'api://test-app-id'
    $env:EXPECTED_ISSUER = 'https://sts.windows.net/test-tenant-id/'
    $env:REQUIRED_ROLE = 'Role.PasswordReset'
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
        
        It 'Should reject request without Authorization header' {
            $Request = @{
                Headers = @{}
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
            }
            
            # Execute function script
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 401
            ($script:response.Body | ConvertFrom-Json).error | Should -Be 'Unauthorized'
        }
        
        It 'Should reject request with invalid Authorization header format' {
            $Request = @{
                Headers = @{ Authorization = 'Invalid token-format' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 401
            ($script:response.Body | ConvertFrom-Json).message | Should -Match 'Bearer'
        }
        
        It 'Should reject request without userId in body' {
            Mock Test-JwtToken {
                $claims = [System.Collections.Generic.List[System.Security.Claims.Claim]]::new()
                $identity = [System.Security.Claims.ClaimsIdentity]::new($claims, 'Bearer')
                [System.Security.Claims.ClaimsPrincipal]::new($identity)
            } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer valid-token' }
                Body    = @{} | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 400
            ($script:response.Body | ConvertFrom-Json).message | Should -Match 'userId'
        }
    }
    
    Context 'JWT Token Validation' {
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
        
        It 'Should reject expired tokens' {
            Mock Test-JwtToken { throw 'Token has expired' } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer expired-token' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 401
        }
        
        It 'Should reject tokens with invalid issuer' {
            Mock Test-JwtToken { throw 'Invalid token issuer' } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer invalid-issuer-token' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
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
            
            Mock Test-JwtToken {
                $claims = [System.Collections.Generic.List[System.Security.Claims.Claim]]::new()
                $identity = [System.Security.Claims.ClaimsIdentity]::new($claims, 'Bearer')
                [System.Security.Claims.ClaimsPrincipal]::new($identity)
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
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer valid-token-no-role' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 403
            ($script:response.Body | ConvertFrom-Json).error | Should -Be 'Forbidden'
        }
        
        It 'Should accept requests with required role' {
            Mock Test-RoleClaim { $true } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer valid-token-with-role' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
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
            
            Mock Test-JwtToken {
                $claims = [System.Collections.Generic.List[System.Security.Claims.Claim]]::new()
                $identity = [System.Security.Claims.ClaimsIdentity]::new($claims, 'Bearer')
                [System.Security.Claims.ClaimsPrincipal]::new($identity)
            } -ModuleName PasswordResetHelpers
            Mock Test-RoleClaim { $true } -ModuleName PasswordResetHelpers
            
            $script:response = $null
            
            function Push-OutputBinding {
                param($Name, $Value)
                $script:response = $Value
            }
        }
        
        It 'Should return generated password on successful reset' {
            Mock New-SecurePassword { 'GeneratedPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer valid-token' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 200
            $responseBody = $script:response.Body | ConvertFrom-Json
            $responseBody.password | Should -Be 'GeneratedPassword123!'
            $responseBody.userId | Should -Be 'user@contoso.com'
        }
        
        It 'Should handle user not found error' {
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { throw 'Resource not found' } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer valid-token' }
                Body    = @{ userId = 'nonexistent@contoso.com' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.StatusCode | Should -Be 500
            ($script:response.Body | ConvertFrom-Json).message | Should -Match 'not found'
        }
        
        It 'Should include security headers in response' {
            Mock New-SecurePassword { 'TestPassword123!' } -ModuleName PasswordResetHelpers
            Mock Set-ADUserPassword { $true } -ModuleName PasswordResetHelpers
            
            $Request = @{
                Headers = @{ Authorization = 'Bearer valid-token' }
                Body    = @{ userId = 'user@contoso.com' } | ConvertTo-Json
            }
            
            $functionScript = Get-Content (Join-Path $script:TestProjectRoot 'ResetUserPassword/run.ps1') -Raw
            Invoke-Expression $functionScript
            
            $script:response.Headers.'Cache-Control' | Should -Match 'no-store'
            $script:response.Headers.'X-Content-Type-Options' | Should -Be 'nosniff'
            $script:response.Headers.'Strict-Transport-Security' | Should -Match 'max-age'
        }
    }
}
