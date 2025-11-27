#!/usr/bin/env powershell
#Requires -Version 5.1

<#
.SYNOPSIS
    Minimal bootstrap for promoting a Windows Server VM to an AD DS domain controller.

.DESCRIPTION
    This script installs the AD DS role and promotes the server to a new forest/domain.
    It intentionally DOES NOT create OUs, service accounts, ACLs, or test users.
    Post-promotion directory provisioning is handled separately by `Configure-ADPostPromotion.ps1`.

    Use this script via Custom Script Extension or Run Command prior to running the post-promotion script.

.PARAMETER DomainName
    The fully qualified domain name (e.g., 'contoso.local').

.PARAMETER DomainNetBiosName
    The NetBIOS name for the domain (e.g., 'CONTOSO').

.PARAMETER SafeModeAdminPassword
    The Directory Services Restore Mode (DSRM) password (must meet complexity requirements).

.EXAMPLE
    .\Bootstrap-ADDSDomain.ps1 -DomainName 'contoso.local' -DomainNetBiosName 'CONTOSO' -SafeModeAdminPassword (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force)

.NOTES
    Author: GitHub Copilot
    Separation of concerns: Promotion only. Post provisioning: Configure-ADPostPromotion.ps1
    Requires: Windows PowerShell 5.1 or later (default on Windows Server 2022). Do NOT require PowerShell 7.x when run via Custom Script Extension.

.LINK
    https://learn.microsoft.com/powershell/module/addsdeployment/install-addsforest?view=windowsserver2022-ps
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainNetBiosName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SafeModeAdminPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Function to write log messages
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Information' { Write-Information -MessageData $logMessage -InformationAction Continue }
        'Warning' { Write-Warning -Message $Message }
        'Error' { Write-Error -Message $Message }
    }
}

try {
    Write-Log "Starting AD DS bootstrap (promotion only) for domain: $DomainName"

    # Check if running as Administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator"
    }

    # Format data disk for AD DS database
    Write-Log "Checking for unformatted disks..."
    $rawDisk = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -First 1
    if ($rawDisk) {
        Write-Log "Formatting disk $($rawDisk.Number) for AD DS data..."
        Initialize-Disk -Number $rawDisk.Number -PartitionStyle GPT -PassThru |
        New-Partition -DriveLetter F -UseMaximumSize |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel 'ADDS_Data' -Confirm:$false
        Write-Log "Disk formatted successfully as F:"
    }
    else {
        Write-Log "No raw disk found; using C: for AD DS data (not recommended for production)"
    }

    $databasePath = if (Test-Path 'F:\') { 'F:\NTDS' } else { 'C:\NTDS' }
    $logPath = if (Test-Path 'F:\') { 'F:\NTDS\Logs' } else { 'C:\NTDS\Logs' }
    $sysvolPath = if (Test-Path 'F:\') { 'F:\SYSVOL' } else { 'C:\SYSVOL' }

    # Install AD DS role
    Write-Log "Installing AD-Domain-Services Windows Feature..."
    $featureResult = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    if ($featureResult.Success) {
        Write-Log "AD-Domain-Services installed successfully"
    }
    else {
        throw "Failed to install AD-Domain-Services feature"
    }

    # Check if already a domain controller
    $isDC = $false
    try {
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    }
    catch {
        Write-Log "Unable to determine domain controller status; proceeding with promotion" -Level Warning
    }

    if ($isDC) {
        Write-Log "Server is already a domain controller; skipping promotion" -Level Warning
    }
    else {
        # Promote to domain controller
        Write-Log "Promoting server to domain controller for domain: $DomainName"
        
        if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Promote to Domain Controller for $DomainName")) {
            Import-Module ADDSDeployment
            # Convert plain text to SecureString locally to avoid CSE argument parsing issues
            $dsrmSecure = ConvertTo-SecureString -String $SafeModeAdminPassword -AsPlainText -Force
            
            Install-ADDSForest `
                -DomainName $DomainName `
                -DomainNetbiosName $DomainNetBiosName `
                -SafeModeAdministratorPassword $dsrmSecure `
                -DatabasePath $databasePath `
                -LogPath $logPath `
                -SysvolPath $sysvolPath `
                -InstallDns:$true `
                -CreateDnsDelegation:$false `
                -NoRebootOnCompletion:$false `
                -Force:$true

            Write-Log "Domain controller promotion initiated; server will reboot"
            # Note: Script execution stops here as the server reboots
        }
    }

    Write-Log "AD DS bootstrap completed successfully (promotion phase only)"
    Write-Log "Domain: $DomainName"
    Write-Log "Next: Run Configure-ADPostPromotion.ps1 for directory provisioning (OU, service account, test users)."

}
catch {
    Write-Log "AD DS bootstrap failed: $_" -Level Error
    throw
}
