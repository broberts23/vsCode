#!/usr/bin/env powershell
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerFqdn,

    [Parameter()]
    [switch]$InstallRsat = $true,

    [Parameter()]
    [switch]$EnableBasicAuth = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:LogDirectory = 'C:\temp'
$script:LogFile = Join-Path $script:LogDirectory ("Configure-ManagementWinRmHttps-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
if (-not (Test-Path $script:LogDirectory)) {
    New-Item -Path $script:LogDirectory -ItemType Directory -Force | Out-Null
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:LogFile -Value "[$timestamp] [$Level] $Message"
}

Write-Log "Starting WinRM HTTPS configuration for '$ComputerFqdn'."

if ($InstallRsat) {
    $rsatCapabilities = @(
        'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',
        'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
    )

    foreach ($capability in $rsatCapabilities) {
        $state = Get-WindowsCapability -Online -Name $capability
        if ($state.State -ne 'Installed') {
            Write-Log "Installing Windows capability '$capability'."
            Add-WindowsCapability -Online -Name $capability | Out-Null
        }
        else {
            Write-Log "Windows capability '$capability' is already installed."
        }
    }
}

Write-Log 'Enabling PowerShell remoting and configuring WinRM authentication settings.'
Enable-PSRemoting -Force
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value ([bool]$EnableBasicAuth)
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value '' -Force

$existingListener = Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -like '*Transport=HTTPS*' } | Select-Object -First 1
$certificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match "CN=$([Regex]::Escape($ComputerFqdn))" } | Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $certificate) {
    Write-Log 'No matching certificate found; creating a new self-signed certificate.'
    $certificateParameters = @{
        DnsName           = $ComputerFqdn
        CertStoreLocation = 'Cert:\LocalMachine\My'
        FriendlyName      = 'WinRM HTTPS Listener'
        KeyAlgorithm      = 'RSA'
        KeyLength         = 2048
        HashAlgorithm     = 'SHA256'
        NotAfter          = (Get-Date).AddYears(2)
    }
    $certificate = New-SelfSignedCertificate @certificateParameters
}
else {
    Write-Log "Reusing existing certificate with thumbprint '$($certificate.Thumbprint)'."
}

if (-not $existingListener -and $PSCmdlet.ShouldProcess($ComputerFqdn, 'Create WinRM HTTPS listener')) {
    $listenerParameters = @{
        Path                  = 'WSMan:\localhost\Listener'
        Transport             = 'HTTPS'
        Address               = '*'
        CertificateThumbPrint = $certificate.Thumbprint
        Force                 = $true
    }
    New-Item @listenerParameters | Out-Null
    Write-Log 'Created WinRM HTTPS listener.'
}
elseif ($existingListener) {
    Write-Log 'Existing WinRM HTTPS listener found; leaving it in place.'
}

Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' | Out-Null
$firewallParameters = @{
    DisplayName = 'Allow WinRM HTTPS 5986'
    Direction   = 'Inbound'
    Action      = 'Allow'
    Protocol    = 'TCP'
    LocalPort   = 5986
    Profile     = 'Any'
    ErrorAction = 'SilentlyContinue'
}
New-NetFirewallRule @firewallParameters | Out-Null
Write-Log 'Ensured firewall rules allow WinRM HTTPS on TCP 5986.'

Restart-Service -Name WinRM
Write-Log 'Restarted WinRM service.'

$cerBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$result = [pscustomobject]@{
    ComputerFqdn      = $ComputerFqdn
    Thumbprint        = $certificate.Thumbprint
    CertificateBase64 = [Convert]::ToBase64String($cerBytes)
}

Write-Log "WinRM HTTPS configuration completed. Log file: $($script:LogFile)"
$result | ConvertTo-Json -Depth 3