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
    # Import module from FunctionApp directory
    $projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $modulePath = Join-Path $projectRoot 'FunctionApp/ResetUserPassword/PasswordResetHelpers.psm1'
    Import-Module $modulePath -Force
    
    # Mock environment variables for LDAPS
    $env:DOMAIN_CONTROLLER_FQDN = 'dc.contoso.local'
    $env:DOMAIN_NAME = 'contoso.local'
}

Describe 'PasswordResetHelpers Module' {
    
    Context 'Module Load' {
        It 'Should load the module successfully' {
            Get-Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Get-ClientPrincipal function' {
            Get-Command Get-ClientPrincipal -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
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
        
        It 'Should export Install-LdapsTrustedCertificate function' {
            Get-Command Install-LdapsTrustedCertificate -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
        
        It 'Should export Get-ADUserDistinguishedName function' {
            Get-Command Get-ADUserDistinguishedName -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
        }
    }
    
    Context 'Get-ClientPrincipal' {
        BeforeAll {
            # Create valid client principal JSON (as returned by App Service Auth)
            $validPrincipal = @{
                auth_typ = 'aad'
                name_typ = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
                role_typ = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
                claims   = @(
                    @{ typ = 'roles'; val = 'Role.PasswordReset' }
                    @{ typ = 'name'; val = 'user@contoso.com' }
                )
            }
            
            $json = $validPrincipal | ConvertTo-Json -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $validHeader = [System.Convert]::ToBase64String($bytes)
        }
        
        It 'Should throw on null header' {
            { Get-ClientPrincipal -HeaderValue $null } | Should -Throw
        }
        
        It 'Should throw on empty header' {
            { Get-ClientPrincipal -HeaderValue '' } | Should -Throw
        }
        
        It 'Should throw on invalid base64' {
            { Get-ClientPrincipal -HeaderValue 'not-valid-base64!!!' } | Should -Throw
        }
        
        It 'Should decode valid client principal header' {
            $result = Get-ClientPrincipal -HeaderValue $validHeader
            $result | Should -Not -BeNullOrEmpty
            $result.auth_typ | Should -Be 'aad'
            $result.claims | Should -Not -BeNullOrEmpty
        }
        
        It 'Should return principal with claims array' {
            $result = Get-ClientPrincipal -HeaderValue $validHeader
            $result.claims | Should -HaveCount 2
            $result.claims[0].typ | Should -Be 'roles'
            $result.claims[0].val | Should -Be 'Role.PasswordReset'
        }
        
        It 'Should handle principal with multiple claims' {
            $principal = @{
                auth_typ = 'aad'
                claims   = @(
                    @{ typ = 'roles'; val = 'Role.PasswordReset' }
                    @{ typ = 'roles'; val = 'Role.Other' }
                    @{ typ = 'name'; val = 'user@contoso.com' }
                )
            }
            
            $json = $principal | ConvertTo-Json -Compress
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            $header = [System.Convert]::ToBase64String($bytes)
            
            $result = Get-ClientPrincipal -HeaderValue $header
            $result.claims | Should -HaveCount 3
        }
    }
    
    Context 'Test-RoleClaim' {
        BeforeAll {
            # Create test client principal with roles
            $principalWithRoles = [PSCustomObject]@{
                auth_typ = 'aad'
                claims   = @(
                    @{ typ = 'roles'; val = 'Role.PasswordReset' }
                    @{ typ = 'roles'; val = 'Role.Other' }
                )
            }
            
            # Principal without role claims
            $principalWithoutRoles = [PSCustomObject]@{
                auth_typ = 'aad'
                claims   = @(
                    @{ typ = 'name'; val = 'user@contoso.com' }
                )
            }
            
            # Principal with no claims
            $principalNoClaims = [PSCustomObject]@{
                auth_typ = 'aad'
            }
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
        
        It 'Should return false when no claims exist' {
            $result = Test-RoleClaim -Principal $principalNoClaims -RequiredRole 'Role.PasswordReset'
            $result | Should -Be $false
        }
        
        It 'Should be case-sensitive for role matching' {
            $result = Test-RoleClaim -Principal $principalWithRoles -RequiredRole 'role.passwordreset'
            $result | Should -Be $false
        }
        
        It 'Should handle role claim type' {
            $principalWithRole = [PSCustomObject]@{
                auth_typ = 'aad'
                claims   = @(
                    @{ typ = 'role'; val = 'Role.PasswordReset' }
                )
            }
            
            $result = Test-RoleClaim -Principal $principalWithRole -RequiredRole 'Role.PasswordReset'
            $result | Should -Be $true
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
    
    Context 'Install-LdapsTrustedCertificate' {
        It 'Should throw on null certificate' {
            { Install-LdapsTrustedCertificate -CertificateBase64 $null } | Should -Throw
        }
        
        It 'Should throw on empty certificate' {
            { Install-LdapsTrustedCertificate -CertificateBase64 '' } | Should -Throw
        }
        
        It 'Should throw on invalid base64' {
            { Install-LdapsTrustedCertificate -CertificateBase64 'not-valid-base64!!!' } | Should -Throw
        }
    }
    
    Context 'Get-ADUserDistinguishedName' {
        It 'Should throw on null SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Get-ADUserDistinguishedName -SamAccountName $null -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Credential $testCred } | Should -Throw
        }
        
        It 'Should throw on empty SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Get-ADUserDistinguishedName -SamAccountName '' -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Credential $testCred } | Should -Throw
        }
    }
    
    Context 'Set-ADUserPassword' {
        BeforeAll {
            # Mock LDAPS functions used by Set-ADUserPassword
            Mock -CommandName Get-ADUserDistinguishedName -MockWith { 'CN=John Doe,OU=Users,DC=contoso,DC=local' } -ModuleName PasswordResetHelpers
        }
        
        It 'Should throw on null SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName $null -Password 'SecurePass123!' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should throw on empty SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName '' -Password 'SecurePass123!' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should throw on null Password' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password $null -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should throw on empty Password' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password '' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should successfully set password via LDAPS' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password 'SecurePass123!' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Confirm:$false } | Should -Not -Throw
            
            Should -Invoke Get-ADUserDistinguishedName -ModuleName PasswordResetHelpers -Times 1
        }
        
        It 'Should throw when user not found' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Mock Get-ADUserDistinguishedName { throw 'User not found' } -ModuleName PasswordResetHelpers
            
            { Set-ADUserPassword -SamAccountName 'nonexistent' -Password 'SecurePass123!' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Confirm:$false } | Should -Throw
        }
        
        It 'Should accept pipeline input for SamAccountName' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { 'jdoe' | Set-ADUserPassword -Password 'SecurePass123!' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Confirm:$false } | Should -Not -Throw
            
            Should -Invoke Get-ADUserDistinguishedName -ModuleName PasswordResetHelpers -Times 1
        }
        
        It 'Should support -WhatIf' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            Set-ADUserPassword -SamAccountName 'jdoe' -Password 'SecurePass123!' -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -WhatIf
            
            # WhatIf should not invoke the actual LDAPS operation
            Should -Invoke Get-ADUserDistinguishedName -ModuleName PasswordResetHelpers -Times 0
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
