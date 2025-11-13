#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Location,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $GitHubRepo, # format: owner/repo

    [Parameter(Mandatory = $false)]
    [string] $GitHubPAT,
    
    [Parameter(Mandatory = $false)]
    [switch] $UseSecretManagement,
    
    [Parameter(Mandatory = $false)]
    [string] $SecretVaultName,
    
    [Parameter(Mandatory = $false)]
    [string] $SecretName = 'GitHub.PAT',

    [Parameter(Mandatory = $false)]
    [string] $TemplatePath = "./infra/main.bicep",

    [Parameter(Mandatory = $false)]
    [hashtable] $TemplateParameters,

    [Parameter(Mandatory = $false)]
    [string] $VirtualNetworkAddressPrefix = '10.10.0.0/16',

    [Parameter(Mandatory = $false)]
    [string] $ContainerAppsSubnetPrefix = '10.10.0.0/23',

    [Parameter(Mandatory = $false)]
    [string] $PlatformReservedCidr = '10.200.0.0/24',

    [Parameter(Mandatory = $false)]
    [string] $PlatformReservedDnsIp = '10.200.0.10',

    [Parameter(Mandatory = $false)]
    [string] $DockerBridgeCidr = '172.16.0.0/16',

    [Parameter(Mandatory = $false)]
    [bool] $InternalEnvironment = $false
)

<#
.NOTES
This script is a convenience wrapper. For security, avoid storing GitHub PATs in files. Use Azure Key Vault or SecretManagement for production.

Az deployment docs: https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest
Container Apps networking parameters: https://learn.microsoft.com/azure/container-apps/vnet-custom?tabs=bash#networking-parameters
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Verbose 'Checking Az module availability...'
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Verbose 'Installing Az module (current user scope)...'
    Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
}

Import-Module Az.Accounts -Force
Import-Module Az.Resources -Force

Write-Verbose 'Ensuring you are logged in to Azure...'
if (-not (Get-AzContext)) {
    Connect-AzAccount | Out-Null
}

if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess("ResourceGroup/$ResourceGroupName", 'Create resource group')) {
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
    }
}

Write-Verbose 'Preparing deployment parameters...'
if (-not $TemplateParameters) {
    $TemplateParameters = @{
        location = @{ value = $Location }
    }
}

# Ensure required template parameters for GitHub owner/repo are present based on -GitHubRepo
if (-not $TemplateParameters.githubOwner -or -not $TemplateParameters.githubRepo) {
    if ($GitHubRepo -notmatch '^([^/]+)/([^/]+)$') {
        throw "-GitHubRepo must be in 'owner/repo' format. Value: '$GitHubRepo'"
    }
    $owner, $repo = $Matches[1], $Matches[2]
    if (-not $TemplateParameters.githubOwner) { $TemplateParameters.githubOwner = @{ value = $owner } }
    if (-not $TemplateParameters.githubRepo) { $TemplateParameters.githubRepo = @{ value = $repo } }
}

# Populate virtual network defaults if not already provided by caller
if (-not $TemplateParameters.virtualNetworkAddressPrefix) {
    $TemplateParameters.virtualNetworkAddressPrefix = @{ value = $VirtualNetworkAddressPrefix }
}
if (-not $TemplateParameters.containerAppsSubnetPrefix) {
    $TemplateParameters.containerAppsSubnetPrefix = @{ value = $ContainerAppsSubnetPrefix }
}
if (-not $TemplateParameters.platformReservedCidr) {
    $TemplateParameters.platformReservedCidr = @{ value = $PlatformReservedCidr }
}
if (-not $TemplateParameters.platformReservedDnsIp) {
    $TemplateParameters.platformReservedDnsIp = @{ value = $PlatformReservedDnsIp }
}
if (-not $TemplateParameters.dockerBridgeCidr) {
    $TemplateParameters.dockerBridgeCidr = @{ value = $DockerBridgeCidr }
}
if (-not $TemplateParameters.internalEnvironment) {
    $TemplateParameters.internalEnvironment = @{ value = $InternalEnvironment }
}

# Helper: resolve GitHub PAT from SecretManagement or Key Vault or parameter
function Resolve-GitHubPAT {
    [CmdletBinding()]
    param(
        [switch] $UseSecretManagement,
        [string] $SecretVaultName,
        [string] $SecretName,
        [string] $GitHubPAT
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # 1) SecretManagement (preferred)
    if ($UseSecretManagement) {
        Write-Verbose 'Attempting to retrieve secret from SecretManagement (Microsoft.PowerShell.SecretManagement)...'
        if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
            Write-Verbose 'Installing Microsoft.PowerShell.SecretManagement...' 
            Install-Module -Name Microsoft.PowerShell.SecretManagement -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module Microsoft.PowerShell.SecretManagement -Force

        try {
            $secret = Get-Secret -Name $SecretName -ErrorAction Stop
            if ($null -ne $secret) {
                Write-Verbose 'Secret retrieved from SecretManagement.'
                return $secret
            }
        }
        catch {
            Write-Verbose "SecretManagement: failed to retrieve secret '$SecretName' - $_"
        }
    }

    # 2) Azure Key Vault (if vault name provided)
    if ($SecretVaultName) {
        Write-Verbose "Attempting to retrieve secret '$SecretName' from Key Vault '$SecretVaultName'..."
        try {
            if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
                Write-Verbose 'Installing Az.KeyVault module...'
                Install-Module -Name Az.KeyVault -Scope CurrentUser -Force -AllowClobber
            }
            Import-Module Az.KeyVault -Force
            $kvSecret = Get-AzKeyVaultSecret -VaultName $SecretVaultName -Name $SecretName -ErrorAction Stop
            if ($kvSecret) {
                Write-Verbose 'Secret retrieved from Azure Key Vault.'
                return $kvSecret.SecretValueText
            }
        }
        catch {
            Write-Verbose "KeyVault: failed to retrieve secret '$SecretName' from vault '$SecretVaultName' - $_"
        }
    }

    # 3) Fallback to provided PAT parameter
    if ($GitHubPAT) {
        Write-Verbose 'Using GitHub PAT provided via parameter.'
        return $GitHubPAT
    }

    return $null
}

# Resolve the PAT now
$ResolvedGitHubPAT = Resolve-GitHubPAT -UseSecretManagement:$UseSecretManagement -SecretVaultName $SecretVaultName -SecretName $SecretName -GitHubPAT $GitHubPAT
if (-not $ResolvedGitHubPAT) {
    Write-Verbose 'No GitHub PAT available (SecretManagement/KeyVault/parameter). The script can still create a federated credential but will not register a runner without a registration token.'
}

if ($PSCmdlet.ShouldProcess($TemplatePath, 'Deploy Bicep template')) {
    # If we have a registration token, add it to container environment variables (additionalEnv)
    if ($ResolvedGitHubPAT) {
        Write-Verbose 'Requesting GitHub runner registration token using provided PAT...'
        function Get-GitHubRegistrationToken {
            param(
                [Parameter(Mandatory = $true)] [string] $Repo,
                [Parameter(Mandatory = $true)] [string] $Pat
            )
            $uri = "https://api.github.com/repos/$Repo/actions/runners/registration-token"
            $auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Pat):"))
            $headers = @{ Authorization = "Basic $auth"; 'User-Agent' = 'ps' }
            try {
                $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType 'application/json'
                return $resp.token
            }
            catch {
                throw "Failed to request registration token: $_"
            }
        }

        try {
            $registrationToken = Get-GitHubRegistrationToken -Repo $GitHubRepo -Pat $ResolvedGitHubPAT
            Write-Verbose 'Registration token obtained.'
            # inject as environment variable parameter expected by the container via 'additionalEnv'
            if (-not $TemplateParameters.additionalEnv) {
                $TemplateParameters.additionalEnv = @{ value = @() }
            }
            $envList = @($TemplateParameters.additionalEnv.value)
            $envList += @{ name = 'RUNNER_TOKEN'; value = $registrationToken }
            $TemplateParameters.additionalEnv = @{ value = $envList }
        }
        catch {
            Write-Warning "Could not obtain registration token: $_"
        }
    }

    $deployment = New-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -TemplateFile $TemplatePath -TemplateParameterObject $TemplateParameters -Verbose
    Write-Output $deployment

    # Try to get the principalId of the job's managed identity from template outputs
    try {
        if ($deployment.Outputs -and $deployment.Outputs.jobPrincipalId) {
            $principalId = $deployment.Outputs.jobPrincipalId.value
        }
    }
    catch {
        Write-Verbose "Could not determine job principalId from deployment outputs: $_"
        $principalId = $null
    }
}

# Create federated credential to allow GitHub OIDC for the job's managed identity (sample)
if ($principalId) {
    $issuer = 'https://token.actions.githubusercontent.com'
    $subject = "repo:$GitHubRepo:ref:refs/heads/main"

    $scriptPath = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath 'Create-FederatedCredential.ps1'
    if (Test-Path $scriptPath) {
        if ($PSCmdlet.ShouldProcess($principalId, 'Add federated credential for GitHub OIDC to managed identity application')) {
            & $scriptPath -AppObjectId $principalId -Name 'github-oidc' -Issuer $issuer -Subject $subject | Write-Output
        }
    }
    else {
        Write-Warning "Federated credential helper not found at $scriptPath"
    }
}
else {
    Write-Warning 'Container group managed identity principalId not available; skipping federated credential creation.'
}
