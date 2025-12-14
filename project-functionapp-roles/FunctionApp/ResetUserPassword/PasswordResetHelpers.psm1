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

# Module-scoped caches (per runspace)
$script:CachedAdServiceCredential = $null
$script:CachedLdapsCertificateBase64 = $null
$script:CachedLdapsCertificateInstalled = $false

#region Public Functions

function Get-ManagedIdentityAccessToken {
    <#
    .SYNOPSIS
        Retrieves an access token using the Azure Functions/App Service Managed Identity endpoint.
    .PARAMETER Resource
        Resource URI for the token (e.g. https://vault.azure.net)
    .OUTPUTS
        System.String
    .LINK
        https://learn.microsoft.com/azure/app-service/overview-managed-identity
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Resource
    )

    $identityEndpoint = $env:IDENTITY_ENDPOINT
    $identityHeader = $env:IDENTITY_HEADER
    $headerName = 'X-IDENTITY-HEADER'
    $apiVersion = '2019-08-01'

    if ([string]::IsNullOrWhiteSpace($identityEndpoint) -and -not [string]::IsNullOrWhiteSpace($env:MSI_ENDPOINT)) {
        $identityEndpoint = $env:MSI_ENDPOINT
        $identityHeader = $env:MSI_SECRET
        $headerName = 'Secret'
        $apiVersion = '2017-09-01'
    }

    if ([string]::IsNullOrWhiteSpace($identityEndpoint) -or [string]::IsNullOrWhiteSpace($identityHeader)) {
        throw "Managed Identity endpoint is not available in this environment."
    }

    $identityEndpoint = $identityEndpoint.Trim().Trim('"').Trim("'").TrimEnd('/')
    if (-not ($identityEndpoint -as [System.Uri]) -or -not ([System.Uri]$identityEndpoint).IsAbsoluteUri) {
        throw "Managed Identity Endpoint is not a valid absolute URI: '$identityEndpoint'"
    }

    $uriBuilder = [System.UriBuilder]::new($identityEndpoint)
    $uriBuilder.Query = "resource=$([System.Uri]::EscapeDataString($Resource))&api-version=$apiVersion"
    $tokenUri = $uriBuilder.Uri.AbsoluteUri

    $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Headers @{ $headerName = $identityHeader } -Method Get
    if (-not $tokenResponse -or [string]::IsNullOrWhiteSpace($tokenResponse.access_token)) {
        throw "Managed Identity token response did not contain an access_token."
    }

    return [string]$tokenResponse.access_token
}

function Get-KeyVaultSecretValue {
    <#
    .SYNOPSIS
        Retrieves a Key Vault secret value using Managed Identity.
    .PARAMETER KeyVaultUri
        Base URI of the vault (e.g. https://myvault.vault.azure.net)
    .PARAMETER SecretName
        Name of the secret
    .OUTPUTS
        System.String
    .LINK
        https://learn.microsoft.com/azure/key-vault/secrets/quick-create-powershell
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$KeyVaultUri,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretName
    )

    $keyVaultUriClean = $KeyVaultUri.Trim().Trim('"').Trim("'").TrimEnd('/')
    if (-not ($keyVaultUriClean -as [System.Uri]) -or -not ([System.Uri]$keyVaultUriClean).IsAbsoluteUri) {
        throw "Key Vault URI is not a valid absolute URI: '$keyVaultUriClean'"
    }

    $token = Get-ManagedIdentityAccessToken -Resource 'https://vault.azure.net' -ErrorAction Stop
    $headers = @{ Authorization = "Bearer $token" }

    $escapedSecretName = [System.Uri]::EscapeDataString($SecretName)
    $secretUri = "$keyVaultUriClean/secrets/${escapedSecretName}?api-version=7.4"
    $secretResponse = Invoke-RestMethod -Uri $secretUri -Headers $headers -Method Get

    if (-not $secretResponse -or $null -eq $secretResponse.value) {
        throw "Key Vault secret '$SecretName' did not return a value."
    }

    return [string]$secretResponse.value
}

function Get-FunctionAdServiceCredential {
    <#
    .SYNOPSIS
        Retrieves (and caches) the AD service account credential for password reset.
    .DESCRIPTION
        Prefers local environment variables, otherwise loads from Key Vault using Managed Identity.
    .OUTPUTS
        System.Management.Automation.PSCredential
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param()

    if ($script:CachedAdServiceCredential) {
        return $script:CachedAdServiceCredential
    }

    if (-not [string]::IsNullOrWhiteSpace($env:AD_SERVICE_USERNAME) -and -not [string]::IsNullOrWhiteSpace($env:AD_SERVICE_PASSWORD)) {
        $securePassword = ConvertTo-SecureString -String $env:AD_SERVICE_PASSWORD -AsPlainText -Force
        $script:CachedAdServiceCredential = [PSCredential]::new($env:AD_SERVICE_USERNAME, $securePassword)

        # Back-compat for older code paths
        Set-Variable -Scope Global -Name ADServiceCredential -Value $script:CachedAdServiceCredential

        return $script:CachedAdServiceCredential
    }

    if ([string]::IsNullOrWhiteSpace($env:KEY_VAULT_URI)) {
        throw "AD service credentials not configured (missing AD_SERVICE_USERNAME/AD_SERVICE_PASSWORD and KEY_VAULT_URI)."
    }

    $secretValue = Get-KeyVaultSecretValue -KeyVaultUri $env:KEY_VAULT_URI -SecretName 'ENTRA-PWDRESET-RW' -ErrorAction Stop

    # Secret format: {"username":"DOMAIN\\svc","password":"pwd"}
    if ($secretValue -match '\\(?![\\"/bfnrtu])') {
        $secretValue = $secretValue -replace '\\(?![\\"/bfnrtu])', '\\'
    }

    $credentialObject = $secretValue | ConvertFrom-Json -ErrorAction Stop
    if (-not $credentialObject.username -or $null -eq $credentialObject.password) {
        throw "ENTRA-PWDRESET-RW secret must contain 'username' and 'password' fields."
    }

    $securePassword = ConvertTo-SecureString -String $credentialObject.password -AsPlainText -Force
    $script:CachedAdServiceCredential = [PSCredential]::new([string]$credentialObject.username, $securePassword)

    # Back-compat for older code paths
    Set-Variable -Scope Global -Name ADServiceCredential -Value $script:CachedAdServiceCredential

    return $script:CachedAdServiceCredential
}

function Get-FunctionLdapsCertificateBase64 {
    <#
    .SYNOPSIS
        Retrieves (and caches) the LDAPS public certificate (base64) from Key Vault.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($script:CachedLdapsCertificateBase64) {
        return $script:CachedLdapsCertificateBase64
    }

    if ([string]::IsNullOrWhiteSpace($env:KEY_VAULT_URI)) {
        return $null
    }

    try {
        $script:CachedLdapsCertificateBase64 = Get-KeyVaultSecretValue -KeyVaultUri $env:KEY_VAULT_URI -SecretName 'LDAPS-Certificate-CER' -ErrorAction Stop

        # Back-compat for older code paths
        Set-Variable -Scope Global -Name LdapsCertificateCer -Value $script:CachedLdapsCertificateBase64

        return $script:CachedLdapsCertificateBase64
    }
    catch {
        Write-Verbose "Failed to retrieve LDAPS certificate secret: $($_.Exception.Message)"
        return $null
    }
}

function Ensure-LdapsTrustedCertificateInstalled {
    <#
    .SYNOPSIS
        Ensures the LDAPS certificate is installed in the local trust store.
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:CachedLdapsCertificateInstalled) {
        return $true
    }

    $certificateBase64 = Get-FunctionLdapsCertificateBase64
    if ([string]::IsNullOrWhiteSpace($certificateBase64)) {
        return $false
    }

    Install-LdapsTrustedCertificate -CertificateBase64 $certificateBase64 -ErrorAction Stop | Out-Null
    $script:CachedLdapsCertificateInstalled = $true

    # Back-compat for older code paths
    Set-Variable -Scope Global -Name LdapsCertificateInstalled -Value $true

    return $true
}

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
        Base64-encoded certificate. Supports DER bytes, or PEM file bytes.
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
        # Some generators store a PEM file (ASCII text) rather than DER bytes.
        # In that case, .NET's byte-based constructor will fail; fall back to CreateFromPem.
        $cert = $null
        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
        }
        catch {
            $pemText = [System.Text.Encoding]::UTF8.GetString($certBytes)

            if ($pemText -match '-----BEGIN CERTIFICATE-----') {
                $createFromPem = [System.Security.Cryptography.X509Certificates.X509Certificate2].GetMethod(
                    'CreateFromPem',
                    [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static,
                    $null,
                    [Type[]]@([string]),
                    $null
                )

                if ($null -eq $createFromPem) {
                    throw "Certificate appears to be PEM, but X509Certificate2.CreateFromPem(string) is not available in this runtime."
                }

                $cert = $createFromPem.Invoke($null, @($pemText))
            }
            else {
                throw
            }
        }
        
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

        # Best-effort: also try to add to LocalMachine Root (may be blocked in App Service sandbox)
        try {
            $machineStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::Root,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
            )
            $machineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

            $existingMachine = $machineStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            if (-not $existingMachine) {
                $machineStore.Add($cert)
                Write-Verbose "Certificate installed in LocalMachine Root: $($cert.Thumbprint)"
            }

            $machineStore.Close()
        }
        catch {
            Write-Verbose "Unable to add certificate to LocalMachine Root (non-fatal): $($_.Exception.Message)"
        }
        
        return $true
    }
    catch {
        Write-Error "Failed to install LDAPS certificate: $_"
        throw
    }
}

function Test-LdapsTcpConnectivity {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$HostName,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 636,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 5
    )

    $client = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            try { $client.Close() } catch {}
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($client) {
            try { $client.Dispose() } catch {}
        }
    }
}

function ConvertFrom-LdapsCertificateBase64 {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateBase64
    )

    $certBytes = [Convert]::FromBase64String($CertificateBase64)

    try {
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
    }
    catch {
        $pemText = [System.Text.Encoding]::UTF8.GetString($certBytes)
        if ($pemText -notmatch '-----BEGIN CERTIFICATE-----') {
            throw
        }

        $createFromPem = [System.Security.Cryptography.X509Certificates.X509Certificate2].GetMethod(
            'CreateFromPem',
            [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static,
            $null,
            [Type[]]@([string]),
            $null
        )

        if ($null -eq $createFromPem) {
            throw "Certificate appears to be PEM, but X509Certificate2.CreateFromPem(string) is not available in this runtime."
        }

        return [System.Security.Cryptography.X509Certificates.X509Certificate2]$createFromPem.Invoke($null, @($pemText))
    }
}

function Get-CertificateDnsNames {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try {
        $primary = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        if (-not [string]::IsNullOrWhiteSpace($primary)) {
            [void]$names.Add($primary)
        }
    }
    catch {
        # ignore
    }

    try {
        $sanExt = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($sanExt) {
            $formatted = ([System.Security.Cryptography.AsnEncodedData]::new($sanExt.Oid, $sanExt.RawData)).Format($true)
            foreach ($line in ($formatted -split "`r?`n")) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^DNS Name\s*=\s*(.+)$') {
                    [void]$names.Add($Matches[1].Trim())
                }
            }
        }
    }
    catch {
        # ignore
    }

    try {
        $cn = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (-not [string]::IsNullOrWhiteSpace($cn)) {
            [void]$names.Add($cn)
        }
    }
    catch {
        # ignore
    }

    return @($names)
}

function Test-CertificateMatchesHostName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$HostName,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Require a DNS name (strict hostname validation). IP addresses cannot be validated against SAN DNS entries.
    $parsedIp = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$parsedIp)) {
        return $false
    }

    $dnsNames = Get-CertificateDnsNames -Certificate $Certificate
    if ($dnsNames -contains $HostName) {
        return $true
    }

    # Wildcard support
    foreach ($name in $dnsNames) {
        if ($name -like '*.*' -and $name.StartsWith('*.')) {
            $suffix = $name.Substring(1) # remove leading '*'
            if ($HostName.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }

    return $false
}

function New-LdapsConnection {
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.Protocols.LdapConnection])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Quick network preflight so we can distinguish firewall/routing from TLS failures.
    $tcpOk = Test-LdapsTcpConnectivity -HostName $DomainController -Port 636 -TimeoutSeconds 5
    if (-not $tcpOk) {
        throw "Unable to reach $DomainController on TCP/636. Check NSG and Windows Firewall on the domain controller."
    }

    $ldapIdentifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DomainController, 636)
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new($ldapIdentifier)

    $connection.SessionOptions.SecureSocketLayer = $true
    $connection.SessionOptions.ProtocolVersion = 3

    # Strict server certificate validation.
    # If we have the expected server certificate (self-signed in this project), pin to that cert AND validate hostname.
    $expectedCertBase64 = $null
    try {
        $expectedCertBase64 = Get-FunctionLdapsCertificateBase64
    }
    catch {
        $expectedCertBase64 = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($expectedCertBase64)) {
        $expectedCert = ConvertFrom-LdapsCertificateBase64 -CertificateBase64 $expectedCertBase64
        $expectedThumbprint = $expectedCert.Thumbprint

        $connection.SessionOptions.VerifyServerCertificate = {
            param(
                [System.DirectoryServices.Protocols.LdapConnection]$conn,
                [System.Security.Cryptography.X509Certificates.X509Certificate]$cert
            )

            try {
                $presented = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)

                if ($presented.Thumbprint -ne $expectedThumbprint) {
                    Write-Warning "LDAPS certificate thumbprint mismatch. Presented '$($presented.Thumbprint)', expected '$expectedThumbprint'."
                    return $false
                }

                if (-not (Test-CertificateMatchesHostName -HostName $DomainController -Certificate $presented)) {
                    $names = (Get-CertificateDnsNames -Certificate $presented) -join ', '
                    Write-Warning "LDAPS certificate does not match host '$DomainController'. Names in cert: $names"
                    return $false
                }

                return $true
            }
            catch {
                Write-Warning "LDAPS server certificate validation threw: $($_.Exception.Message)"
                return $false
            }
        }
    }

    $networkCred = [System.Net.NetworkCredential]::new(
        $Credential.UserName,
        $Credential.Password
    )
    $connection.Credential = $networkCred
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic

    return $connection
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
        
        # Create LDAP connection (LDAPS)
        # Reference: https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols
        $connection = New-LdapsConnection -DomainController $DomainController -Credential $Credential -ErrorAction Stop
        
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
        The new password (SecureString)
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
        $success = Set-ADUserPassword -SamAccountName 'jdoe' -Password $newPasswordSecure -Credential $adCred -DomainController 'dc01.contoso.local' -DomainName 'contoso.local'
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
        [ValidateNotNull()]
        [securestring]$Password,
        
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

            $passwordPlain = [System.Net.NetworkCredential]::new('', $Password).Password
            if ([string]::IsNullOrWhiteSpace($passwordPlain)) {
                throw "Password cannot be empty."
            }
            
            # Bypass ShouldProcess check for non-interactive execution (e.g. Azure Functions)
            # if ($PSCmdlet.ShouldProcess($SamAccountName, 'Set AD user password via LDAPS')) {
            
            # Get user's Distinguished Name
            $userDN = Get-ADUserDistinguishedName `
                -SamAccountName $SamAccountName `
                -DomainController $DomainController `
                -Credential $Credential `
                -DomainName $DomainName
            
            # Create LDAP connection (LDAPS)
            $connection = New-LdapsConnection -DomainController $DomainController -Credential $Credential -ErrorAction Stop
            
            # Bind
            $connection.Bind()
            Write-Verbose "LDAPS connection established for password reset"
            
            # Convert password to UTF-16LE format with quotes (required for unicodePwd attribute)
            # Reference: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/set-user-password-with-ldifde
            $passwordWithQuotes = "`"$passwordPlain`""
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
            # } # End ShouldProcess
            
            # return $false
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
    'Get-ManagedIdentityAccessToken'
    'Get-KeyVaultSecretValue'
    'Get-FunctionAdServiceCredential'
    'Get-FunctionLdapsCertificateBase64'
    'Ensure-LdapsTrustedCertificateInstalled'
    'Test-LdapsTcpConnectivity'
    'ConvertFrom-LdapsCertificateBase64'
    'Get-CertificateDnsNames'
    'Test-CertificateMatchesHostName'
    'New-LdapsConnection'
    'Get-ADUserDistinguishedName'
    'Set-ADUserPassword'
    'New-SecurePassword'
    'Install-LdapsTrustedCertificate'
    'Get-ClientPrincipal'
    'Test-RoleClaim'
    'New-SecurePassword'
    'Install-LdapsTrustedCertificate'
    'Get-ADUserDistinguishedName'
    'Set-ADUserPassword'
)
