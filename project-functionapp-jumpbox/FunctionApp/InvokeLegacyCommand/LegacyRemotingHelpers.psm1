#!/usr/bin/env pwsh
#Requires -Version 7.4

using namespace System.Security.Cryptography.X509Certificates
using namespace System.Net.Security
using namespace System.Net.Sockets

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CachedJumpboxCredential = $null
$script:CachedJumpboxCertificate = $null

function Get-ResolvedAppSettingValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "App setting '$Name' is required."
    }

    if ($value.StartsWith('@Microsoft.KeyVault(', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "App setting '$Name' still contains an unresolved Key Vault reference. In Azure, ensure the Function App managed identity can read the secret. For local development, provide the raw secret value in local.settings.json."
    }

    return [string]$value
}

function Get-FunctionJumpboxCredential {
    [CmdletBinding()]
    [OutputType([pscredential])]
    param()

    if ($script:CachedJumpboxCredential) {
        return $script:CachedJumpboxCredential
    }

    $secretValue = Get-ResolvedAppSettingValue -Name 'MANAGEMENT_CREDENTIAL_JSON'
    if ($secretValue -match '\\(?![\\"/bfnrtu])') {
        $secretValue = $secretValue -replace '\\(?![\\"/bfnrtu])', '\\'
    }

    $credentialObject = $secretValue | ConvertFrom-Json -ErrorAction Stop
    $securePassword = ConvertTo-SecureString -String $credentialObject.password -AsPlainText -Force
    $script:CachedJumpboxCredential = [pscredential]::new([string]$credentialObject.username, $securePassword)
    return $script:CachedJumpboxCredential
}

function Get-FunctionJumpboxCertificate {
    [CmdletBinding()]
    [OutputType([X509Certificate2])]
    param()

    if ($script:CachedJumpboxCertificate) {
        return $script:CachedJumpboxCertificate
    }

    $base64Value = Get-ResolvedAppSettingValue -Name 'WINRM_CERTIFICATE_BASE64'
    $script:CachedJumpboxCertificate = [X509Certificate2]::new([Convert]::FromBase64String($base64Value))
    return $script:CachedJumpboxCertificate
}

function Normalize-CertificateThumbprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Thumbprint
    )

    return ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
}

function Test-CertificateDnsName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
    )

    $dnsName = $Certificate.GetNameInfo([X509NameType]::DnsName, $false)
    if ([string]::IsNullOrWhiteSpace($dnsName)) {
        return $false
    }

    if ($dnsName.StartsWith('*.', [System.StringComparison]::Ordinal)) {
        $suffix = $dnsName.Substring(1)
        return $ComputerName.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)
    }

    return $dnsName.Equals($ComputerName, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-RemoteTlsCertificateInfo {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 5986
    )

    $capturedCertificate = $null
    $capturedPolicyErrors = [SslPolicyErrors]::None
    $tcpClient = [TcpClient]::new()

    try {
        $tcpClient.Connect($ComputerName, $Port)

        $callback = [RemoteCertificateValidationCallback] {
            param($sender, $certificate, $chain, $sslPolicyErrors)

            if ($certificate) {
                $script:capturedCertificate = [X509Certificate2]::new($certificate)
            }

            $script:capturedPolicyErrors = $sslPolicyErrors
            return $true
        }

        $sslStream = [SslStream]::new($tcpClient.GetStream(), $false, $callback)
        try {
            $sslStream.AuthenticateAsClient($ComputerName)
        }
        finally {
            $sslStream.Dispose()
        }

        if (-not $script:capturedCertificate) {
            throw "No TLS certificate was presented by ${ComputerName}:$Port."
        }

        return [pscustomobject]@{
            Certificate  = $script:capturedCertificate
            PolicyErrors = $script:capturedPolicyErrors
        }
    }
    finally {
        if ($tcpClient.Connected) {
            $tcpClient.Dispose()
        }

        Remove-Variable -Scope Script -Name capturedCertificate -ErrorAction SilentlyContinue
        Remove-Variable -Scope Script -Name capturedPolicyErrors -ErrorAction SilentlyContinue
    }
}

function Test-WinRmTlsPinning {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [X509Certificate2]$ExpectedCertificate,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 5986
    )

    $remoteInfo = Get-RemoteTlsCertificateInfo -ComputerName $ComputerName -Port $Port
    $expectedThumbprint = Normalize-CertificateThumbprint -Thumbprint $ExpectedCertificate.Thumbprint
    $remoteThumbprint = Normalize-CertificateThumbprint -Thumbprint $remoteInfo.Certificate.Thumbprint

    if ($remoteThumbprint -ne $expectedThumbprint) {
        throw "Jumpbox certificate pinning failed. Expected thumbprint '$expectedThumbprint' but received '$remoteThumbprint'."
    }

    if (-not (Test-CertificateDnsName -Certificate $remoteInfo.Certificate -ComputerName $ComputerName)) {
        throw "Jumpbox certificate DNS identity does not match '$ComputerName'."
    }

    return [pscustomobject]@{
        ComputerName = $ComputerName
        Port         = $Port
        Thumbprint   = $remoteThumbprint
        Subject      = $remoteInfo.Certificate.Subject
        PolicyErrors = [string]$remoteInfo.PolicyErrors
    }
}

function New-ValidatedLegacyPSSession {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [X509Certificate2]$ExpectedCertificate,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 5986
    )

    $null = Test-WinRmTlsPinning -ComputerName $ComputerName -ExpectedCertificate $ExpectedCertificate -Port $Port
    $sessionOption = New-PSSessionOption -SkipCACheck
    $sessionParameters = @{ 
        ComputerName   = $ComputerName
        UseSSL         = $true
        Port           = $Port
        Authentication = 'Basic'
        Credential     = $Credential
        SessionOption  = $sessionOption
    }

    return New-PSSession @sessionParameters
}

function Invoke-LegacyRemoteScriptBlock {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscredential]$Credential,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [X509Certificate2]$ExpectedCertificate,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptText,

        [Parameter()]
        [hashtable]$Arguments = @{},

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 5986,

        [Parameter()]
        [ValidateRange(5, 1800)]
        [int]$TimeoutSeconds = 300
    )

    $session = $null
    $job = $null
    $tlsValidation = Test-WinRmTlsPinning -ComputerName $ComputerName -ExpectedCertificate $ExpectedCertificate -Port $Port

    try {
        $sessionOption = New-PSSessionOption -SkipCACheck
        $sessionParameters = @{ 
            ComputerName   = $ComputerName
            UseSSL         = $true
            Port           = $Port
            Authentication = 'Basic'
            Credential     = $Credential
            SessionOption  = $sessionOption
        }
        $session = New-PSSession @sessionParameters

        $jobParameters = @{ 
            Session      = $session
            AsJob        = $true
            ScriptBlock  = {
                param($RemoteScriptText, $RemoteArguments)

                Set-StrictMode -Version Latest
                $ErrorActionPreference = 'Stop'
                $VerbosePreference = 'Continue'
                $InformationPreference = 'Continue'

                $result = & ([scriptblock]::Create($RemoteScriptText)) @RemoteArguments 6>&1 5>&1 4>&1 3>&1 2>&1
                $normalized = foreach ($item in $result) {
                    if ($item -is [System.Management.Automation.ErrorRecord]) {
                        "ERROR: $($item.ToString())"
                    }
                    elseif ($item -is [System.Management.Automation.WarningRecord]) {
                        "WARNING: $($item.Message)"
                    }
                    elseif ($item -is [System.Management.Automation.VerboseRecord]) {
                        "VERBOSE: $($item.Message)"
                    }
                    elseif ($item -is [System.Management.Automation.InformationRecord]) {
                        "INFO: $($item.MessageData)"
                    }
                    else {
                        $item
                    }
                }

                [pscustomobject]@{
                    computerName = $env:COMPUTERNAME
                    identity     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    output       = @($normalized)
                }
            }
            ArgumentList = @($ScriptText, $Arguments)
        }

        $job = Invoke-Command @jobParameters

        if (-not (Wait-Job -Job $job -Timeout $TimeoutSeconds)) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            throw "Remote execution timed out after $TimeoutSeconds seconds."
        }

        $remoteResult = Receive-Job -Job $job -AutoRemoveJob
        return [pscustomobject]@{
            tls    = $tlsValidation
            remote = $remoteResult
        }
    }
    finally {
        if ($job) {
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }

        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

function Get-ClientPrincipal {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$HeaderValue
    )

    $bytes = [Convert]::FromBase64String($HeaderValue)
    $json = [System.Text.Encoding]::UTF8.GetString($bytes)
    return $json | ConvertFrom-Json -ErrorAction Stop
}

function Test-RoleClaim {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Principal,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RequiredRole
    )

    $claims = @($Principal.claims)
    foreach ($claim in $claims) {
        if ($claim.typ -eq 'roles' -and $claim.val -eq $RequiredRole) {
            return $true
        }
    }

    return $false
}

Export-ModuleMember -Function @(
    'Get-FunctionJumpboxCredential',
    'Get-FunctionJumpboxCertificate',
    'Normalize-CertificateThumbprint',
    'Test-CertificateDnsName',
    'Test-WinRmTlsPinning',
    'New-ValidatedLegacyPSSession',
    'Invoke-LegacyRemoteScriptBlock',
    'Get-ClientPrincipal',
    'Test-RoleClaim'
)