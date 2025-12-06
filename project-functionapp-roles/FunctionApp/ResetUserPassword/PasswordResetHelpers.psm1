#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Module for JWT validation and password reset operations
.DESCRIPTION
    Provides functions for validating JWT tokens, checking role claims,
    generating secure passwords, and resetting user passwords in on-premises Active Directory
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Public Functions

function Get-ClientPrincipal {
    <#
    .SYNOPSIS
        Decodes the X-MS-CLIENT-PRINCIPAL header from Azure Functions authentication middleware
    .DESCRIPTION
        Parses and decodes the base64-encoded client principal header injected by
        App Service / Functions built-in authentication (Easy Auth)
    .PARAMETER HeaderValue
        The base64-encoded X-MS-CLIENT-PRINCIPAL header value
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
        $principal = Get-ClientPrincipal -HeaderValue $Request.Headers['X-MS-CLIENT-PRINCIPAL']
    .LINK
        https://learn.microsoft.com/azure/app-service/configure-authentication-user-identities
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$HeaderValue
    )
    
    Process {
        try {
            Write-Verbose "Decoding X-MS-CLIENT-PRINCIPAL header"
            
            # Decode base64 header
            $bytes = [System.Convert]::FromBase64String($HeaderValue)
            $json = [System.Text.Encoding]::UTF8.GetString($bytes)
            
            # Parse JSON
            $principal = $json | ConvertFrom-Json
            
            if (-not $principal) {
                throw "Failed to parse client principal JSON"
            }
            
            Write-Verbose "Client principal decoded successfully. Auth type: $($principal.auth_typ)"
            return $principal
        }
        catch {
            Write-Error "Failed to decode client principal: $_"
            throw
        }
    }
}

function Test-RoleClaim {
    <#
    .SYNOPSIS
        Tests if a client principal has a specific role
    .DESCRIPTION
        Checks if the provided client principal (decoded from X-MS-CLIENT-PRINCIPAL) contains the required role claim
    .PARAMETER Principal
        The client principal object (decoded from X-MS-CLIENT-PRINCIPAL header)
    .PARAMETER RequiredRole
        The required role claim value
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        $principal = Get-ClientPrincipal -HeaderValue $Request.Headers['X-MS-CLIENT-PRINCIPAL']
        $hasRole = Test-RoleClaim -Principal $principal -RequiredRole 'Role.PasswordReset'
    .LINK
        https://learn.microsoft.com/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Principal,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RequiredRole
    )
    
    Process {
        try {
            Write-Verbose "Checking for role claim: $RequiredRole"
            
            # Check if principal has claims property
            if (-not $Principal.PSObject.Properties['claims']) {
                Write-Verbose "No claims property found in principal"
                return $false
            }
            
            # Check if claims array exists and is not empty
            if (-not $Principal.claims) {
                Write-Verbose "No claims found in principal"
                return $false
            }
            
            # Get all role claims
            # Roles can be in 'roles' or 'role' claim type
            $roleClaims = @($Principal.claims | Where-Object { $_.typ -eq 'roles' -or $_.typ -eq 'role' })
            
            if ($roleClaims.Count -eq 0) {
                Write-Verbose "No role claims found in principal"
                return $false
            }
            
            # Check if required role exists (case-sensitive)
            $roleValues = @($roleClaims | ForEach-Object { $_.val })
            $hasRole = $roleValues -ccontains $RequiredRole
            
            Write-Verbose "Role claim check result: $hasRole"
            return $hasRole
        }
        catch {
            Write-Error "Role claim validation failed: $_"
            throw
        }
    }
}

function New-SecurePassword {
    <#
    .SYNOPSIS
        Generates a cryptographically secure random password
    .DESCRIPTION
        Creates a random password meeting Azure AD complexity requirements:
        - Minimum 12 characters
        - Contains uppercase, lowercase, numbers, and special characters
    .PARAMETER Length
        Password length (default: 16)
    .OUTPUTS
        System.String
    .EXAMPLE
        $password = New-SecurePassword -Length 20
    .LINK
        https://learn.microsoft.com/azure/active-directory/authentication/concept-password-policies
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [ValidateRange(12, 256)]
        [int]$Length = 16
    )
    
    Process {
        try {
            Write-Verbose "Generating secure password of length $Length"
            
            # Character sets for password complexity
            $lowercase = 'abcdefghijkmnopqrstuvwxyz'
            $uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
            $numbers = '23456789'
            $special = '!@#$%^&*'
            
            # Ensure at least one character from each set
            $password = [System.Collections.ArrayList]::new()
            [void]$password.Add($lowercase[(Get-Random -Maximum $lowercase.Length)])
            [void]$password.Add($uppercase[(Get-Random -Maximum $uppercase.Length)])
            [void]$password.Add($numbers[(Get-Random -Maximum $numbers.Length)])
            [void]$password.Add($special[(Get-Random -Maximum $special.Length)])
            
            # Fill remaining length with random characters from all sets
            $allChars = $lowercase + $uppercase + $numbers + $special
            for ($i = $password.Count; $i -lt $Length; $i++) {
                [void]$password.Add($allChars[(Get-Random -Maximum $allChars.Length)])
            }
            
            # Shuffle the password array using Fisher-Yates algorithm
            for ($i = $password.Count - 1; $i -gt 0; $i--) {
                $j = Get-Random -Maximum ($i + 1)
                $temp = $password[$i]
                $password[$i] = $password[$j]
                $password[$j] = $temp
            }
            
            $result = -join $password
            
            Write-Verbose "Secure password generated successfully"
            return $result
        }
        catch {
            Write-Error "Password generation failed: $_"
            throw
        }
    }
}

function Install-LdapsTrustedCertificate {
    <#
    .SYNOPSIS
        Installs a trusted root certificate for LDAPS connections
    .DESCRIPTION
        Retrieves the LDAPS certificate from Key Vault and installs it in the
        current user's Trusted Root Certification Authorities store
    .PARAMETER CertificateBase64
        Base64-encoded certificate (DER format)
    .OUTPUTS
        System.Boolean
    .LINK
        https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509certificate2
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateBase64
    )
    
    try {
        Write-Verbose "Installing LDAPS trusted certificate..."
        
        # Decode certificate from base64
        $certBytes = [Convert]::FromBase64String($CertificateBase64)
        
        # Create X509Certificate2 object
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        
        # Open the Trusted Root store for the current user
        # Reference: https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509store
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::Root,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        
        # Check if certificate already exists
        $existingCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        
        if (-not $existingCert) {
            $store.Add($cert)
            Write-Verbose "Certificate installed: $($cert.Thumbprint)"
        }
        else {
            Write-Verbose "Certificate already exists: $($cert.Thumbprint)"
        }
        
        $store.Close()
        
        return $true
    }
    catch {
        Write-Error "Failed to install LDAPS certificate: $_"
        throw
    }
}

function Get-ADUserDistinguishedName {
    <#
    .SYNOPSIS
        Retrieves a user's Distinguished Name from Active Directory via LDAPS
    .DESCRIPTION
        Performs an LDAPS search to find a user by sAMAccountName and returns their DN
    .PARAMETER SamAccountName
        The user's sAMAccountName
    .PARAMETER DomainController
        Domain controller FQDN or IP address
    .PARAMETER Credential
        Service account credential for LDAP bind
    .PARAMETER DomainName
        The AD domain name (e.g., 'contoso.local')
    .OUTPUTS
        System.String
    .LINK
        https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols.ldapconnection
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,
        
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName
    )
    
    try {
        Write-Verbose "Searching for user DN: $SamAccountName"
        
        # Create LDAP connection
        # Reference: https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols
        $ldapIdentifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DomainController, 636)
        $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($ldapIdentifier)
        
        # Configure for LDAPS (SSL/TLS)
        $connection.SessionOptions.SecureSocketLayer = $true
        $connection.SessionOptions.ProtocolVersion = 3
        
        # Set authentication credentials
        $networkCred = [System.Net.NetworkCredential]::new(
            $Credential.UserName,
            $Credential.Password
        )
        $connection.Credential = $networkCred
        $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        
        # Bind to verify connection
        $connection.Bind()
        Write-Verbose "LDAPS connection established"
        
        # Build search base from domain name
        $domainComponents = $DomainName.Split('.') | ForEach-Object { "DC=$_" }
        $searchBase = $domainComponents -join ','
        
        # Create search request
        $searchRequest = [System.DirectoryServices.Protocols.SearchRequest]::new(
            $searchBase,
            "(sAMAccountName=$SamAccountName)",
            [System.DirectoryServices.Protocols.SearchScope]::Subtree,
            @('distinguishedName')
        )
        
        # Execute search
        $searchResponse = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($searchRequest)
        
        if ($searchResponse.Entries.Count -eq 0) {
            throw "User not found: $SamAccountName"
        }
        
        if ($searchResponse.Entries.Count -gt 1) {
            Write-Warning "Multiple users found for sAMAccountName: $SamAccountName - using first result"
        }
        
        $userEntry = $searchResponse.Entries[0]
        $distinguishedName = $userEntry.Attributes['distinguishedName'][0]
        
        Write-Verbose "Found user DN: $distinguishedName"
        
        return $distinguishedName
    }
    catch {
        Write-Error "Failed to retrieve user DN for $SamAccountName : $_"
        throw
    }
    finally {
        if ($connection) {
            $connection.Dispose()
        }
    }
}

function Set-ADUserPassword {
    <#
    .SYNOPSIS
        Sets a user's password in on-premises Active Directory via LDAPS
    .DESCRIPTION
        Updates the password for a specified user in Active Directory Domain Services (ADDS)
        using LDAPS connection (without requiring AD PowerShell module)
    .PARAMETER SamAccountName
        The user's sAMAccountName
    .PARAMETER Password
        The new password (plain text)
    .PARAMETER Credential
        Service account credential with permissions to reset passwords in AD
    .PARAMETER DomainController
        Domain controller FQDN or IP address
    .PARAMETER DomainName
        The AD domain name (e.g., 'contoso.local')
    .PARAMETER ChangePasswordAtLogon
        Whether user must change password at next logon (not implemented via LDAPS)
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        $success = Set-ADUserPassword -SamAccountName 'jdoe' -Password $newPassword -Credential $adCred -DomainController 'dc01.contoso.local' -DomainName 'contoso.local'
    .LINK
        https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols.modifyrequest
    .LINK
        https://learn.microsoft.com/troubleshoot/windows-server/active-directory/set-user-password-with-ldifde
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$SamAccountName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,
        
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName,
        
        [Parameter()]
        [bool]$ChangePasswordAtLogon = $false
    )
    
    Process {
        $connection = $null
        try {
            Write-Verbose "Setting password for AD user via LDAPS: $SamAccountName"
            
            if ($PSCmdlet.ShouldProcess($SamAccountName, 'Set AD user password via LDAPS')) {
                # Get user's Distinguished Name
                $userDN = Get-ADUserDistinguishedName `
                    -SamAccountName $SamAccountName `
                    -DomainController $DomainController `
                    -Credential $Credential `
                    -DomainName $DomainName
                
                # Create LDAP connection
                $ldapIdentifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DomainController, 636)
                $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($ldapIdentifier)
                
                # Configure for LDAPS
                $connection.SessionOptions.SecureSocketLayer = $true
                $connection.SessionOptions.ProtocolVersion = 3
                
                # Set authentication
                $networkCred = [System.Net.NetworkCredential]::new(
                    $Credential.UserName,
                    $Credential.Password
                )
                $connection.Credential = $networkCred
                $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
                
                # Bind
                $connection.Bind()
                Write-Verbose "LDAPS connection established for password reset"
                
                # Convert password to UTF-16LE format with quotes (required for unicodePwd attribute)
                # Reference: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/set-user-password-with-ldifde
                $passwordWithQuotes = "`"$Password`""
                $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes($passwordWithQuotes)
                
                # Create modify request for unicodePwd attribute
                $modifyRequest = [System.DirectoryServices.Protocols.ModifyRequest]::new(
                    $userDN,
                    [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace,
                    'unicodePwd',
                    $passwordBytes
                )
                
                # Execute password reset
                $modifyResponse = [System.DirectoryServices.Protocols.ModifyResponse]$connection.SendRequest($modifyRequest)
                
                if ($modifyResponse.ResultCode -eq [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    Write-Verbose "Password set successfully for AD user: $SamAccountName"
                    
                    if ($ChangePasswordAtLogon) {
                        Write-Warning "ChangePasswordAtLogon not implemented via LDAPS in this version"
                    }
                    
                    return $true
                }
                else {
                    throw "LDAP modify failed with result code: $($modifyResponse.ResultCode)"
                }
            }
            
            return $false
        }
        catch {
            Write-Error "Failed to set password via LDAPS for AD user $SamAccountName : $_"
            throw
        }
        finally {
            if ($connection) {
                $connection.Dispose()
            }
        }
    }
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Get-ClientPrincipal'
    'Test-RoleClaim'
    'New-SecurePassword'
    'Install-LdapsTrustedCertificate'
    'Get-ADUserDistinguishedName'
    'Set-ADUserPassword'
)
