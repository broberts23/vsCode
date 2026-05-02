#!/usr/bin/env pwsh
#Requires -Version 7.4

using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

$projectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$modulePath = Join-Path $projectRoot 'FunctionApp/InvokeLegacyCommand/LegacyRemotingHelpers.psm1'
Import-Module $modulePath -Force

function New-TestDnsCertificate {
    param(
        [Parameter(Mandatory)]
        [string]$DnsName
    )

    $rsa = [RSA]::Create(2048)

    try {
        $request = [CertificateRequest]::new(
            "CN=$DnsName",
            $rsa,
            [HashAlgorithmName]::SHA256,
            [RSASignaturePadding]::Pkcs1)
        $subjectAlternativeName = [SubjectAlternativeNameBuilder]::new()
        $subjectAlternativeName.AddDnsName($DnsName)
        $request.CertificateExtensions.Add($subjectAlternativeName.Build($false))

        return $request.CreateSelfSigned((Get-Date).AddDays(-1), (Get-Date).AddDays(7))
    }
    finally {
        $rsa.Dispose()
    }
}

Describe 'Normalize-CertificateThumbprint' {
    It 'removes separators and uppercases the thumbprint' {
        $result = Normalize-CertificateThumbprint -Thumbprint 'aa bb:cc-dd'
        $result | Should Be 'AABBCCDD'
    }
}

Describe 'Test-CertificateDnsName' {
    It 'matches the certificate DNS name to the requested host' {
        $certificate = New-TestDnsCertificate -DnsName 'server.contoso.local'

        Test-CertificateDnsName -Certificate $certificate -ComputerName 'server.contoso.local' | Should Be $true
        Test-CertificateDnsName -Certificate $certificate -ComputerName 'other.contoso.local' | Should Be $false
    }
}

Describe 'Test-RoleClaim' {
    It 'returns true when the required role claim exists' {
        $principal = [pscustomobject]@{
            claims = @(
                [pscustomobject]@{ typ = 'roles'; val = 'Role.LegacyCommand.Invoke' }
            )
        }

        Test-RoleClaim -Principal $principal -RequiredRole 'Role.LegacyCommand.Invoke' | Should Be $true
    }

    It 'returns false when the required role claim is missing' {
        $principal = [pscustomobject]@{
            claims = @(
                [pscustomobject]@{ typ = 'roles'; val = 'Role.Other' }
            )
        }

        Test-RoleClaim -Principal $principal -RequiredRole 'Role.LegacyCommand.Invoke' | Should Be $false
    }
}