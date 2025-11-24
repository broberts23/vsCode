#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Configure Active Directory post-promotion by creating service accounts and test users.

.DESCRIPTION
    This script runs after the domain controller is promoted and creates the required
    service account for the function app and test users for validation.

    This script should be executed via Azure VM Run Command after the DC promotion completes.

.PARAMETER DomainName
    The fully qualified domain name (e.g., 'contoso.local').

.PARAMETER ServiceAccountName
    The name of the service account for the function app (default: 'svc-functionapp').

.PARAMETER ServiceAccountPassword
    The password for the service account (must meet complexity requirements).

.EXAMPLE
    .\Configure-ADPostPromotion.ps1 -DomainName 'contoso.local' -ServiceAccountPassword (ConvertTo-SecureString 'SvcP@ss123!' -AsPlainText -Force)

.NOTES
    Author: GitHub Copilot
    Requires: Windows PowerShell 5.1 or later (runs on Windows Server)
    This script must be run on the domain controller after promotion.

.LINK
    https://learn.microsoft.com/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps

.LINK
    https://learn.microsoft.com/powershell/module/activedirectory/new-adorganizationalunit?view=windowsserver2022-ps
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountName = 'svc-functionapp',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [securestring]$ServiceAccountPassword
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
    Write-Log "Starting AD configuration for domain: $DomainName"

    # Wait for AD Web Services
    Write-Log "Waiting for AD Web Services to be available..."
    $timeout = 300
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Get-ADDomain -ErrorAction Stop | Out-Null
            Write-Log "AD Web Services is available"
            break
        } catch {
            Start-Sleep -Seconds 10
            $elapsed += 10
            Write-Log "Waiting for AD Web Services... ($elapsed/$timeout seconds)" -Level Warning
        }
    }

    if ($elapsed -ge $timeout) {
        throw "Timed out waiting for AD Web Services"
    }

    # Create Organizational Unit for function app resources
    Write-Log "Creating Organizational Unit: FunctionAppResources"
    $domainDN = (Get-ADDomain).DistinguishedName
    $ouPath = "OU=FunctionAppResources,$domainDN"
    
    try {
        Get-ADOrganizationalUnit -Identity $ouPath -ErrorAction Stop | Out-Null
        Write-Log "OU already exists: $ouPath" -Level Warning
    } catch {
        if ($PSCmdlet.ShouldProcess($ouPath, "Create Organizational Unit")) {
            New-ADOrganizationalUnit -Name 'FunctionAppResources' -Path $domainDN -ProtectedFromAccidentalDeletion $true
            Write-Log "OU created successfully"
        }
    }

    # Create service account for function app
    Write-Log "Creating service account: $ServiceAccountName"
    $serviceAccountParams = @{
        Name                  = $ServiceAccountName
        SamAccountName        = $ServiceAccountName
        UserPrincipalName     = "$ServiceAccountName@$DomainName"
        AccountPassword       = $ServiceAccountPassword
        Enabled               = $true
        PasswordNeverExpires  = $true
        CannotChangePassword  = $true
        Path                  = $ouPath
        Description           = 'Service account for Azure Function App password reset operations'
    }

    try {
        Get-ADUser -Identity $ServiceAccountName -ErrorAction Stop | Out-Null
        Write-Log "Service account already exists: $ServiceAccountName" -Level Warning
        
        # Update password if account exists
        if ($PSCmdlet.ShouldProcess($ServiceAccountName, "Update password")) {
            Set-ADAccountPassword -Identity $ServiceAccountName -NewPassword $ServiceAccountPassword -Reset
            Write-Log "Service account password updated"
        }
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        if ($PSCmdlet.ShouldProcess($ServiceAccountName, "Create service account")) {
            New-ADUser @serviceAccountParams
            Write-Log "Service account created successfully"
        }
    }

    # Grant password reset permissions to service account
    Write-Log "Granting password reset permissions to service account..."
    $serviceAccountSID = (Get-ADUser -Identity $ServiceAccountName).SID
    
    # Get current ACL
    $acl = Get-Acl -Path "AD:\$domainDN"
    
    # Create ACE for password reset (extended right: Reset Password)
    # GUID reference: https://learn.microsoft.com/windows/win32/adschema/r-user-force-change-password
    $passwordResetGuid = [GUID]'00299570-246d-11d0-a768-00aa006e0529'
    $userObjectGuid = [GUID]'bf967aba-0de6-11d0-a285-00aa003049e2'
    
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $serviceAccountSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $passwordResetGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $userObjectGuid
    )
    
    if ($PSCmdlet.ShouldProcess($domainDN, "Add password reset ACE")) {
        $acl.AddAccessRule($ace)
        Set-Acl -Path "AD:\$domainDN" -AclObject $acl
        Write-Log "Password reset permission granted"
    }

    # Create test users
    Write-Log "Creating test users..."
    $testUsers = @(
        @{ Name = 'testuser1'; DisplayName = 'Test User 1'; Description = 'Test account for password reset validation' }
        @{ Name = 'testuser2'; DisplayName = 'Test User 2'; Description = 'Test account for password reset validation' }
        @{ Name = 'testuser3'; DisplayName = 'Test User 3'; Description = 'Test account for password reset validation' }
    )

    foreach ($user in $testUsers) {
        $initialPassword = ConvertTo-SecureString 'InitialP@ss123!' -AsPlainText -Force
        $userParams = @{
            Name                 = $user.Name
            SamAccountName       = $user.Name
            UserPrincipalName    = "$($user.Name)@$DomainName"
            DisplayName          = $user.DisplayName
            AccountPassword      = $initialPassword
            Enabled              = $true
            ChangePasswordAtLogon = $false
            Path                 = $ouPath
            Description          = $user.Description
        }

        try {
            Get-ADUser -Identity $user.Name -ErrorAction Stop | Out-Null
            Write-Log "User already exists: $($user.Name)" -Level Warning
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($PSCmdlet.ShouldProcess($user.Name, "Create test user")) {
                New-ADUser @userParams
                Write-Log "Test user created: $($user.Name)"
            }
        }
    }

    Write-Log "AD configuration completed successfully"
    Write-Log "Domain: $DomainName"
    Write-Log "Service Account: $ServiceAccountName"
    Write-Log "Test Users: $($testUsers.Name -join ', ')"
    Write-Log "Test User Initial Password: InitialP@ss123!"

} catch {
    Write-Log "AD configuration failed: $_" -Level Error
    Write-Log "Exception Type: $($_.Exception.GetType().FullName)" -Level Error
    Write-Log "Stack Trace: $($_.Exception.StackTrace)" -Level Error
    throw
}
