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
        
        It 'Should export ConvertFrom-LdapsCertificateBase64 function' {
            Get-Command ConvertFrom-LdapsCertificateBase64 -Module PasswordResetHelpers | Should -Not -BeNullOrEmpty
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
            $script:validHeader = [System.Convert]::ToBase64String($bytes)
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
            $result = Get-ClientPrincipal -HeaderValue $script:validHeader
            $result | Should -Not -BeNullOrEmpty
            $result.auth_typ | Should -Be 'aad'
            $result.claims | Should -Not -BeNullOrEmpty
        }
        
        It 'Should return principal with claims array' {
            $result = Get-ClientPrincipal -HeaderValue $script:validHeader
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
            $script:principalWithRoles = [PSCustomObject]@{
                auth_typ = 'aad'
                claims   = @(
                    @{ typ = 'roles'; val = 'Role.PasswordReset' }
                    @{ typ = 'roles'; val = 'Role.Other' }
                )
            }
            
            # Principal without role claims
            $script:principalWithoutRoles = [PSCustomObject]@{
                auth_typ = 'aad'
                claims   = @(
                    @{ typ = 'name'; val = 'user@contoso.com' }
                )
            }
            
            # Principal with no claims
            $script:principalNoClaims = [PSCustomObject]@{
                auth_typ = 'aad'
            }
        }
        
        It 'Should throw on null principal' {
            { Test-RoleClaim -Principal $null -RequiredRole 'Role.PasswordReset' } | Should -Throw
        }
        
        It 'Should return true when required role exists' {
            $result = Test-RoleClaim -Principal $script:principalWithRoles -RequiredRole 'Role.PasswordReset'
            $result | Should -Be $true
        }
        
        It 'Should return false when required role does not exist' {
            $result = Test-RoleClaim -Principal $script:principalWithRoles -RequiredRole 'Role.NonExistent'
            $result | Should -Be $false
        }
        
        It 'Should return false when no roles exist' {
            $result = Test-RoleClaim -Principal $script:principalWithoutRoles -RequiredRole 'Role.PasswordReset'
            $result | Should -Be $false
        }
        
        It 'Should return false when no claims exist' {
            $result = Test-RoleClaim -Principal $script:principalNoClaims -RequiredRole 'Role.PasswordReset'
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
    
    Context 'ConvertFrom-LdapsCertificateBase64' {
        It 'Should throw on null certificate' {
            { ConvertFrom-LdapsCertificateBase64 -CertificateBase64 $null } | Should -Throw
        }

        It 'Should throw on empty certificate' {
            { ConvertFrom-LdapsCertificateBase64 -CertificateBase64 '' } | Should -Throw
        }

        It 'Should throw on invalid base64' {
            { ConvertFrom-LdapsCertificateBase64 -CertificateBase64 'not-valid-base64!!!' } | Should -Throw
        }

        It 'Should parse a valid DER certificate' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=unit-test-der',
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $cert = $req.CreateSelfSigned([datetime]::UtcNow.AddMinutes(-1), [datetime]::UtcNow.AddDays(7))

            $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $base64 = [Convert]::ToBase64String($bytes)

            $parsed = ConvertFrom-LdapsCertificateBase64 -CertificateBase64 $base64
            $parsed | Should -Not -BeNullOrEmpty
            $parsed.Thumbprint | Should -Be $cert.Thumbprint
        }

        It 'Should parse a valid PEM certificate' {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=unit-test-pem',
                $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $cert = $req.CreateSelfSigned([datetime]::UtcNow.AddMinutes(-1), [datetime]::UtcNow.AddDays(7))

            $pem = $cert.ExportCertificatePem()
            $pemBytes = [System.Text.Encoding]::UTF8.GetBytes($pem)
            $base64 = [Convert]::ToBase64String($pemBytes)

            $parsed = ConvertFrom-LdapsCertificateBase64 -CertificateBase64 $base64
            $parsed | Should -Not -BeNullOrEmpty
            $parsed.Thumbprint | Should -Be $cert.Thumbprint
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
            # Note: Set-ADUserPassword creates actual LDAPS connections using .NET types
            # Unit tests focus on parameter validation and function interface
            # Integration tests should test actual LDAPS connectivity
            Mock -CommandName Get-ADUserDistinguishedName -MockWith { 
                throw 'User not found' 
            } -ModuleName PasswordResetHelpers
        }
        
        It 'Should throw on null SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            $pw = ConvertTo-SecureString 'SecurePass123!' -AsPlainText -Force
            { Set-ADUserPassword -SamAccountName $null -Password $pw -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should throw on empty SamAccountName' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            $pw = ConvertTo-SecureString 'SecurePass123!' -AsPlainText -Force
            { Set-ADUserPassword -SamAccountName '' -Password $pw -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should throw on null Password' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password $null -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should throw on empty Password' {
            $testCred = [PSCredential]::new('testuser', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            $pwEmpty = [System.Security.SecureString]::new()
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password $pwEmpty -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' } | Should -Throw
        }
        
        It 'Should attempt to get user DN when called with valid parameters' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            $pw = ConvertTo-SecureString 'SecurePass123!' -AsPlainText -Force
            
            # This will fail at Get-ADUserDistinguishedName (mocked to throw), which is expected for unit test
            { Set-ADUserPassword -SamAccountName 'jdoe' -Password $pw -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Confirm:$false } | Should -Throw
            
            Should -Invoke Get-ADUserDistinguishedName -ModuleName PasswordResetHelpers -Times 1 -ParameterFilter {
                $SamAccountName -eq 'jdoe' -and
                $DomainController -eq 'dc.contoso.local' -and
                $DomainName -eq 'contoso.local'
            }
        }
        
        It 'Should throw when user not found' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            $pw = ConvertTo-SecureString 'SecurePass123!' -AsPlainText -Force
            Mock Get-ADUserDistinguishedName { throw 'User not found' } -ModuleName PasswordResetHelpers
            
            { Set-ADUserPassword -SamAccountName 'nonexistent' -Password $pw -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Confirm:$false } | Should -Throw '*User not found*'
        }
        
        It 'Should accept pipeline input for SamAccountName' {
            $testCred = [PSCredential]::new('CONTOSO\\svc-test', (ConvertTo-SecureString 'testpass' -AsPlainText -Force))
            $pw = ConvertTo-SecureString 'SecurePass123!' -AsPlainText -Force
            
            # This will fail at Get-ADUserDistinguishedName (mocked to throw), which is expected for unit test
            { 'jdoe' | Set-ADUserPassword -Password $pw -Credential $testCred -DomainController 'dc.contoso.local' -DomainName 'contoso.local' -Confirm:$false } | Should -Throw
            
            Should -Invoke Get-ADUserDistinguishedName -ModuleName PasswordResetHelpers -Times 1
        }
        
        It 'Should have required parameters defined' {
            $command = Get-Command Set-ADUserPassword -Module PasswordResetHelpers
            $command.Parameters.ContainsKey('SamAccountName') | Should -Be $true
            $command.Parameters.ContainsKey('Password') | Should -Be $true
            $command.Parameters.ContainsKey('Credential') | Should -Be $true
            $command.Parameters.ContainsKey('DomainController') | Should -Be $true
            $command.Parameters.ContainsKey('DomainName') | Should -Be $true
        }
        
        It 'Should support ShouldProcess (WhatIf/Confirm)' {
            $command = Get-Command Set-ADUserPassword -Module PasswordResetHelpers
            $command.Parameters.ContainsKey('WhatIf') | Should -Be $true
            $command.Parameters.ContainsKey('Confirm') | Should -Be $true
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
