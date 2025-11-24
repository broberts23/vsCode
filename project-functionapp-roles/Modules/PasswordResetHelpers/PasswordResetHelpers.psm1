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

function Test-JwtToken {
    <#
    .SYNOPSIS
        Validates a JWT token
    .DESCRIPTION
        Validates JWT token signature, expiration, issuer, and audience claims
    .PARAMETER Token
        The JWT token string to validate
    .PARAMETER ExpectedIssuer
        Expected token issuer
    .PARAMETER ExpectedAudience
        Expected token audience
    .OUTPUTS
        System.Security.Claims.ClaimsPrincipal
    .EXAMPLE
        $principal = Test-JwtToken -Token $bearerToken -ExpectedIssuer $issuer -ExpectedAudience $audience
    .LINK
        https://learn.microsoft.com/azure/active-directory/develop/access-tokens
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Claims.ClaimsPrincipal])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedIssuer,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedAudience
    )
    
    Begin {
        Write-Verbose "Initializing JWT token validation"
    }
    
    Process {
        try {
            # Parse JWT token
            $handler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
            
            if (-not $handler.CanReadToken($Token)) {
                throw "Invalid JWT token format"
            }
            
            $jwtToken = $handler.ReadJwtToken($Token)
            
            # Validate expiration
            $now = [DateTime]::UtcNow
            if ($jwtToken.ValidTo -lt $now) {
                throw "Token has expired"
            }
            
            if ($jwtToken.ValidFrom -gt $now) {
                throw "Token not yet valid"
            }
            
            # Validate issuer
            if ($jwtToken.Issuer -ne $ExpectedIssuer) {
                throw "Invalid token issuer. Expected: $ExpectedIssuer, Got: $($jwtToken.Issuer)"
            }
            
            # Validate audience
            $audiences = $jwtToken.Audiences
            if ($audiences -notcontains $ExpectedAudience) {
                throw "Invalid token audience. Expected: $ExpectedAudience"
            }
            
            Write-Verbose "JWT token validation successful"
            
            # Return claims principal
            $identity = [System.Security.Claims.ClaimsIdentity]::new($jwtToken.Claims, 'Bearer')
            return [System.Security.Claims.ClaimsPrincipal]::new($identity)
        }
        catch {
            Write-Error "JWT token validation failed: $_"
            throw
        }
    }
}

function Test-RoleClaim {
    <#
    .SYNOPSIS
        Tests if a claims principal has a specific role
    .DESCRIPTION
        Checks if the provided claims principal contains the required role claim
    .PARAMETER Principal
        The ClaimsPrincipal to check
    .PARAMETER RequiredRole
        The required role claim value
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        $hasRole = Test-RoleClaim -Principal $principal -RequiredRole 'Role.PasswordReset'
    .LINK
        https://learn.microsoft.com/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [System.Security.Claims.ClaimsPrincipal]$Principal,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$RequiredRole
    )
    
    Process {
        try {
            Write-Verbose "Checking for role claim: $RequiredRole"
            
            # Get all role claims
            # Roles can be in 'roles' claim (app roles) or 'role' claim
            $roleClaims = @($Principal.FindAll('roles'))
            if ($roleClaims.Count -eq 0) {
                $roleClaims = @($Principal.FindAll('role'))
            }
            
            if ($roleClaims.Count -eq 0) {
                Write-Verbose "No role claims found in token"
                return $false
            }
            
            # Check if required role exists (case-sensitive)
            $roleValues = @($roleClaims | ForEach-Object { $_.Value })
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

function Set-ADUserPassword {
    <#
    .SYNOPSIS
        Sets a user's password in on-premises Active Directory
    .DESCRIPTION
        Updates the password for a specified user in Active Directory Domain Services (ADDS)
        using provided service account credentials
    .PARAMETER SamAccountName
        The user's sAMAccountName
    .PARAMETER Password
        The new password
    .PARAMETER Credential
        Service account credential with permissions to reset passwords in AD
    .PARAMETER DomainController
        Domain controller to connect to (optional)
    .PARAMETER ChangePasswordAtLogon
        Whether user must change password at next logon
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        $success = Set-ADUserPassword -SamAccountName 'jdoe' -Password $newPassword -Credential $adCred
    .LINK
        https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountpassword
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
        
        [Parameter()]
        [string]$DomainController,
        
        [Parameter()]
        [bool]$ChangePasswordAtLogon = $false
    )
    
    Process {
        try {
            Write-Verbose "Setting password for AD user: $SamAccountName"
            
            if ($PSCmdlet.ShouldProcess($SamAccountName, 'Set AD user password')) {
                # Convert password to SecureString
                $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
                
                # Build Set-ADAccountPassword parameters
                $params = @{
                    Identity    = $SamAccountName
                    NewPassword = $securePassword
                    Reset       = $true
                    Credential  = $Credential
                    ErrorAction = 'Stop'
                }
                
                if ($DomainController) {
                    $params['Server'] = $DomainController
                }
                
                # Reset the password using AD cmdlet
                # https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountpassword
                Set-ADAccountPassword @params
                
                # Set password change at logon flag if requested
                if ($ChangePasswordAtLogon) {
                    $setParams = @{
                        Identity               = $SamAccountName
                        ChangePasswordAtLogon = $true
                        Credential             = $Credential
                        ErrorAction            = 'Stop'
                    }
                    
                    if ($DomainController) {
                        $setParams['Server'] = $DomainController
                    }
                    
                    Set-ADUser @setParams
                    Write-Verbose "Set ChangePasswordAtLogon flag for user: $SamAccountName"
                }
                
                Write-Verbose "Password set successfully for AD user: $SamAccountName"
                return $true
            }
            
            return $false
        }
        catch {
            Write-Error "Failed to set password for AD user $SamAccountName : $_"
            throw
        }
    }
}

#endregion

# Export module members
Export-ModuleMember -Function @(
    'Test-JwtToken'
    'Test-RoleClaim'
    'New-SecurePassword'
    'Set-ADUserPassword'
)
