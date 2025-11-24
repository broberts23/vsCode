#!/usr/bin/env pwsh
#Requires -Version 7.4

using namespace System.Security.Claims
using namespace System.IdentityModel.Tokens.Jwt
using namespace System.Collections.Generic

<#
.SYNOPSIS
    Pester tests for PasswordResetHelpers module
.DESCRIPTION
    Unit tests for JWT validation, role checking, password generation, and password setting
.LINK
    https://pester.dev
#>

BeforeAll {
    # Load JWT dependencies
    $binPath = Join-Path $PSScriptRoot '../../bin'
    Add-Type -Path "$binPath/Microsoft.IdentityModel.Abstractions.dll"
    Add-Type -Path "$binPath/Microsoft.IdentityModel.Logging.dll"
    Add-Type -Path "$binPath/Microsoft.IdentityModel.Tokens.dll"
    Add-Type -Path "$binPath/Microsoft.IdentityModel.JsonWebTokens.dll"
    Add-Type -Path "$binPath/System.IdentityModel.Tokens.Jwt.dll"
    
    # Import module
    $modulePath = Join-Path $PSScriptRoot '../../Modules/PasswordResetHelpers/PasswordResetHelpers.psm1'
    Import-Module $modulePath -Force
    
    # Mock AD cmdlets (not available in test environment)
    function Set-ADAccountPassword {
        [CmdletBinding(SupportsShouldProcess)]
        param($Identity, $NewPassword, $Reset, $Credential, $Server)
    }
    function Set-ADUser {
        [CmdletBinding(SupportsShouldProcess)]
        param($Identity, $ChangePasswordAtLogon, $Credential, $Server)
    }
}

Describe 'PasswordResetHelpers Module' {
    
    Context 'Module Load' {
        It 'Should load the module successfully' {
            Get-Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-JwtToken function' {
            Get-Command Test-JwtToken -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Test-RoleClaim function' {
            Get-Command Test-RoleClaim -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export New-SecurePassword function' {
            Get-Command New-SecurePassword -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Set-ADUserPassword function' {
            Get-Command Set-ADUserPassword -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Test-JwtToken' {
        BeforeAll {
            $validIssuer = 'https://sts.windows.net/tenant-id/'
            $validAudience = 'api://app-id'
            
            # Create a valid JWT token for testing
            $claims = [System.Collections.Generic.List[System.Security.Claims.Claim]]::new()
            $claims.Add([System.Security.Claims.Claim]::new('roles', 'Role.PasswordReset'))
            $claims.Add([System.Security.Claims.Claim]::new('aud', $validAudience))
            
            $notBefore = [DateTime]::UtcNow.AddMinutes(-5)
            $expires = [DateTime]::UtcNow.AddHours(1)
            
            $jwtToken = [System.IdentityModel.Tokens.Jwt.JwtSecurityToken]::new(
                $validIssuer,
                $validAudience,
                $claims,
                $notBefore,
                $expires
            )
            
            $handler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
            $validToken = $handler.WriteToken($jwtToken)
        }
        
        It 'Should throw on null token' {
            { Test-JwtToken -Token $null -ExpectedIssuer $validIssuer -ExpectedAudience $validAudience } | Should -Throw
        }
        
        It 'Should throw on empty token' {
            { Test-JwtToken -Token '' -ExpectedIssuer $validIssuer -ExpectedAudience $validAudience } | Should -Throw
        }
        
        It 'Should throw on invalid token format' {
            { Test-JwtToken -Token 'not-a-jwt-token' -ExpectedIssuer $validIssuer -ExpectedAudience $validAudience } | Should -Throw
        }
        
        It 'Should validate a properly formatted JWT token' {
            $result = Test-JwtToken -Token $validToken -ExpectedIssuer $validIssuer -ExpectedAudience $validAudience
            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType [System.Security.Claims.ClaimsPrincipal]
        }
        
        It 'Should throw on expired token' {
            # Create expired token
            $claims = [System.Collections.Generic.List[System.Security.Claims.Claim]]::new()
            $claims.Add([System.Security.Claims.Claim]::new('aud', $validAudience))
            
            $notBefore = [DateTime]::UtcNow.AddHours(-2)
            $expires = [DateTime]::UtcNow.AddHours(-1)
            
            $expiredToken = [System.IdentityModel.Tokens.Jwt.JwtSecurityToken]::new(
                $validIssuer,
                $validAudience,
                $claims,
                $notBefore,
                $expires
            )
            
            $handler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
            $tokenString = $handler.WriteToken($expiredToken)
            
            { Test-JwtToken -Token $tokenString -ExpectedIssuer $validIssuer -ExpectedAudience $validAudience } | Should -Throw '*expired*'
        }
        
        It 'Should throw on invalid issuer' {
            { Test-JwtToken -Token $validToken -ExpectedIssuer 'https://wrong-issuer/' -ExpectedAudience $validAudience } | Should -Throw '*issuer*'
        }
        
        It 'Should throw on invalid audience' {
            { Test-JwtToken -Token $validToken -ExpectedIssuer $validIssuer -ExpectedAudience 'api://wrong-audience' } | Should -Throw '*audience*'
        }
    }
    
    Context 'Test-RoleClaim' {
        BeforeAll {
            # Create test claims principal
            $claims = [System.Collections.Generic.List[System.Security.Claims.Claim]]::new()
            $claims.Add([System.Security.Claims.Claim]::new('roles', 'Role.PasswordReset'))
            $claims.Add([System.Security.Claims.Claim]::new('roles', 'Role.Other'))
            
            $identity = [System.Security.Claims.ClaimsIdentity]::new($claims)
            $principalWithRoles = [System.Security.Claims.ClaimsPrincipal]::new($identity)
            
            # Principal without role claims
            $emptyIdentity = [System.Security.Claims.ClaimsIdentity]::new()
            $principalWithoutRoles = [System.Security.Claims.ClaimsPrincipal]::new($emptyIdentity)
        }
        
        It 'Should throw on null principal' {
            { Test-RoleClaim -Principal $null -RequiredRole 'Role.PasswordReset' } | Should -Throw
        }
        
        It 'Should return true when required role exists' {
            $result = Test-RoleClaim -Principal $principalWithRoles -RequiredRole 'Role.PasswordReset'
            $result | Should -Be $true
        }
        
        It 'Should return false when required role does not exist' {
            $result = Test-RoleClaim -Principal $principalWithRoles -RequiredRole 'Role.NonExistent'
            $result | Should -Be $false
        }
        
        It 'Should return false when no roles exist' {
            $result = Test-RoleClaim -Principal $principalWithoutRoles -RequiredRole 'Role.PasswordReset'
            $result | Should -Be $false
        }
        
        It 'Should be case-sensitive for role matching' {
            $result = Test-RoleClaim -Principal $principalWithRoles -RequiredRole 'role.passwordreset'
            $result | Should -Be $false
        }
    }
    
    Context 'New-SecurePassword' {
        It 'Should generate a password of default length' {
            $password = New-SecurePassword
            $password.Length | Should -Be 16
        }
        
        It 'Should generate a password of specified length' {
            $password = New-SecurePassword -Length 20
            $password.Length | Should -Be 20
        }
        
        It 'Should generate password with minimum length' {
            $password = New-SecurePassword -Length 12
            $password.Length | Should -Be 12
        }
        
        It 'Should throw for length below minimum' {
            { New-SecurePassword -Length 11 } | Should -Throw
        }
        
        It 'Should throw for length above maximum' {
            { New-SecurePassword -Length 257 } | Should -Throw
        }
        
        It 'Should contain at least one lowercase character' {
            $password = New-SecurePassword
            $password | Should -Match '[a-z]'
        }
        
        It 'Should contain at least one uppercase character' {
            $password = New-SecurePassword
            $password | Should -Match '[A-Z]'
        }
        
        It 'Should contain at least one number' {
            $password = New-SecurePassword
            $password | Should -Match '[0-9]'
        }
        
        It 'Should contain at least one special character' {
            $password = New-SecurePassword
            $password | Should -Match '[!@#$%^&*]'
        }
        
        It 'Should generate unique passwords' {
            $password1 = New-SecurePassword
            $password2 = New-SecurePassword
            $password1 | Should -Not -Be $password2
        }
        
        It 'Should generate passwords consistently meeting complexity requirements' {
            1..10 | ForEach-Object {
                $password = New-SecurePassword
                $password | Should -Match '[a-z]'
                $password | Should -Match '[A-Z]'
                $password | Should -Match '[0-9]'
                $password | Should -Match '[!@#$%^&*]'
            }
        }
    }
    
    Context 'Set-ADUserPassword' {
        BeforeAll {
            # Mock AD cmdlets that would be called by the module
            Mock -CommandName Set-ADAccountPassword -MockWith { } -ModuleName PasswordResetHelpers
            Mock -CommandName Set-ADUser -MockWith { } -ModuleName PasswordResetHelpers
        }
        
        It 'Should throw on null SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName $null -Password 'SecurePass123!' -Credential $testCred } | Should -Throw
        }
        
        It 'Should throw on empty SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName '' -Password 'SecurePass123!' -Credential $testCred } | Should -Throw
        }
        
        It 'Should throw on null Password' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password $null -Credential $testCred } | Should -Throw
        }
        
        It 'Should throw on empty Password' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password '' -Credential $testCred } | Should -Throw
        }
        
        It 'Should call Set-ADAccountPassword with correct parameters' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Set-ADUserPassword -SamAccountName 'jdoe' -Password 'SecurePass123!' -Credential $testCred -Confirm:$false
            
            Should -Invoke Set-ADAccountPassword -ModuleName PasswordResetHelpers -Times 1
        }
        
        It 'Should call Set-ADUser for password change requirement' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Set-ADUserPassword -SamAccountName 'jdoe' -Password 'SecurePass123!' -Credential $testCred -ChangePasswordAtLogon $true -Confirm:$false
            
            Should -Invoke Set-ADUser -ModuleName PasswordResetHelpers -Times 1
        }
        
        It 'Should support ChangePasswordAtLogon parameter' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Set-ADUserPassword -SamAccountName 'jdoe' -Password 'SecurePass123!' -Credential $testCred -ChangePasswordAtLogon $true -Confirm:$false
            
            Should -Invoke Set-ADUser -ModuleName PasswordResetHelpers -Times 1 -ParameterFilter {
                $ChangePasswordAtLogon -eq $true
            }
        }
        
        It 'Should throw when Set-ADAccountPassword fails' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Mock Set-ADAccountPassword { throw 'Cannot find an object with identity' } -ModuleName PasswordResetHelpers
            
            { Set-ADUserPassword -SamAccountName 'nonexistent' -Password 'SecurePass123!' -Credential $testCred -Confirm:$false } | Should -Throw
        }
        
        It 'Should accept pipeline input for SamAccountName' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            'jdoe' | Set-ADUserPassword -Password 'SecurePass123!' -Credential $testCred -Confirm:$false
            
            Should -Invoke Set-ADAccountPassword -ModuleName PasswordResetHelpers -Times 1
        }
        
        It 'Should support -WhatIf' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Set-ADUserPassword -SamAccountName 'jdoe' -Password 'SecurePass123!' -Credential $testCred -WhatIf
            
            Should -Invoke Set-ADAccountPassword -ModuleName PasswordResetHelpers -Times 0
        }
    }
}

Describe 'PasswordResetHelpers Module Integration Tests' -Tag 'Integration' {
    Context 'End-to-End Password Generation and Validation' {
        It 'Should generate password that meets all requirements' {
            $password = New-SecurePassword -Length 20
            
            # Length check
            $password.Length | Should -Be 20
            
            # Complexity checks
            $hasLower = $password -cmatch '[a-z]'
            $hasUpper = $password -cmatch '[A-Z]'
            $hasDigit = $password -match '\d'
            $hasSpecial = $password -match '[!@#$%^&*]'
            
            $hasLower | Should -Be $true
            $hasUpper | Should -Be $true
            $hasDigit | Should -Be $true
            $hasSpecial | Should -Be $true
        }
    }
}
