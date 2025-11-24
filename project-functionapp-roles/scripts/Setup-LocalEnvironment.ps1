#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Sets up the local development environment for the Password Reset Function App.

.DESCRIPTION
    This script prepares your local machine for developing and testing the Function App:
    - Verifies prerequisites (PowerShell 7.4, Azure Functions Core Tools, modules)
    - Creates/updates local.settings.json with proper configuration
    - Installs required PowerShell modules
    - Optionally authenticates to Azure and Microsoft Graph

.PARAMETER TenantId
    Your Entra ID tenant ID.

.PARAMETER AppId
    The Application ID (Client ID) from your App Registration.

.PARAMETER AppIdUri
    The App ID URI for JWT audience validation (e.g., api://password-reset-xxx).

.PARAMETER SkipModuleInstall
    Skip installing PowerShell modules.

.PARAMETER SkipAuthentication
    Skip authenticating to Azure and Microsoft Graph.

.EXAMPLE
    ./Setup-LocalEnvironment.ps1 `
        -TenantId "12345678-1234-1234-1234-123456789abc" `
        -AppId "87654321-4321-4321-4321-210987654321" `
        -AppIdUri "api://password-reset-abcdef"

.LINK
    https://learn.microsoft.com/azure/azure-functions/functions-run-local
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$AppId,

    [Parameter()]
    [string]$AppIdUri,

    [Parameter()]
    [switch]$SkipModuleInstall,

    [Parameter()]
    [switch]$SkipAuthentication
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ====================================
# Functions
# ====================================

function Write-StatusMessage {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $color = switch ($Type) {
        'Info' { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
    }
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor $color
}

function Test-Prerequisites {
    $issues = @()
    
    Write-StatusMessage "Checking prerequisites..." -Type Info
    
    # PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7 -or ($PSVersionTable.PSVersion.Major -eq 7 -and $PSVersionTable.PSVersion.Minor -lt 4)) {
        $issues += "PowerShell 7.4+ required. Current: $($PSVersionTable.PSVersion)"
    }
    else {
        Write-StatusMessage "✓ PowerShell $($PSVersionTable.PSVersion)" -Type Success
    }
    
    # Azure Functions Core Tools
    $funcPath = Get-Command 'func' -ErrorAction SilentlyContinue
    if (-not $funcPath) {
        $issues += "Azure Functions Core Tools not found. Install: https://learn.microsoft.com/azure/azure-functions/functions-run-local"
    }
    else {
        $funcVersion = (func --version 2>&1) -replace '[^\d.]', ''
        Write-StatusMessage "✓ Azure Functions Core Tools v$funcVersion" -Type Success
    }
    
    # Bicep (optional but recommended)
    $bicepPath = Get-Command 'bicep' -ErrorAction SilentlyContinue
    if (-not $bicepPath) {
        Write-StatusMessage "⚠ Bicep CLI not found (optional). Install: https://learn.microsoft.com/azure/azure-resource-manager/bicep/install" -Type Warning
    }
    else {
        $bicepVersion = (bicep --version 2>&1) -match 'version\s+([\d.]+)' | Out-Null; $matches[1]
        Write-StatusMessage "✓ Bicep CLI v$bicepVersion" -Type Success
    }
    
    if ($issues) {
        Write-StatusMessage "`nPrerequisite issues found:" -Type Error
        $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        return $false
    }
    
    Write-StatusMessage "All prerequisites satisfied!" -Type Success
    return $true
}

function Install-RequiredModules {
    if ($SkipModuleInstall) {
        Write-StatusMessage "Skipping module installation" -Type Warning
        return
    }
    
    Write-StatusMessage "Checking PowerShell modules..." -Type Info
    
    $requiredModules = @{
        'Az.Accounts'                    = '2.*'
        'Az.Functions'                   = '4.*'
        'Az.Resources'                   = '6.*'
        'Microsoft.Graph.Authentication' = '2.*'
        'Microsoft.Graph.Applications'   = '2.*'
        'Microsoft.Graph.Users'          = '2.*'
        'Pester'                         = '5.*'
    }
    
    foreach ($moduleName in $requiredModules.Keys) {
        $minVersion = $requiredModules[$moduleName]
        $installed = Get-Module -Name $moduleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
        
        if (-not $installed) {
            if ($PSCmdlet.ShouldProcess($moduleName, 'Install module')) {
                Write-StatusMessage "Installing $moduleName..." -Type Info
                Install-Module -Name $moduleName -MinimumVersion $minVersion -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
                Write-StatusMessage "✓ $moduleName installed" -Type Success
            }
        }
        else {
            Write-StatusMessage "✓ $moduleName $($installed.Version)" -Type Success
        }
    }
}

function New-LocalSettingsFile {
    param(
        [string]$ProjectRoot,
        [string]$TenantId,
        [string]$AppIdUri
    )
    
    $localSettingsPath = Join-Path $ProjectRoot 'local.settings.json'
    
    $issuer = if ($TenantId) {
        "https://sts.windows.net/$TenantId/"
    }
    else {
        "https://sts.windows.net/YOUR_TENANT_ID/"
    }
    
    $audience = if ($AppIdUri) {
        $AppIdUri
    }
    else {
        "api://YOUR_APP_ID"
    }
    
    $localSettings = @{
        IsEncrypted = $false
        Values      = [ordered]@{
            AzureWebJobsStorage                 = 'UseDevelopmentStorage=true'
            FUNCTIONS_WORKER_RUNTIME            = 'powershell'
            FUNCTIONS_WORKER_RUNTIME_VERSION    = '7.4'
            FUNCTIONS_WORKER_PROCESS_COUNT      = '2'
            PSWorkerInProcConcurrencyUpperBound = '10'
            TENANT_ID                           = if ($TenantId) { $TenantId } else { 'YOUR_TENANT_ID' }
            EXPECTED_AUDIENCE                   = $audience
            EXPECTED_ISSUER                     = $issuer
            REQUIRED_ROLE                       = 'Role.PasswordReset'
            KEY_VAULT_URI                       = 'https://your-keyvault.vault.azure.net/'
        }
    }
    
    if (Test-Path $localSettingsPath) {
        Write-StatusMessage "local.settings.json already exists" -Type Warning
        $overwrite = Read-Host "Overwrite existing file? (y/N)"
        if ($overwrite -ne 'y') {
            Write-StatusMessage "Skipping local.settings.json creation" -Type Info
            return
        }
    }
    
    if ($PSCmdlet.ShouldProcess($localSettingsPath, 'Create local.settings.json')) {
        $localSettings | ConvertTo-Json -Depth 10 | Set-Content -Path $localSettingsPath
        Write-StatusMessage "✓ Created local.settings.json" -Type Success
        
        if (-not $TenantId) {
            Write-StatusMessage "Remember to update TENANT_ID, EXPECTED_AUDIENCE, and EXPECTED_ISSUER" -Type Warning
        }
    }
}

function Connect-ToAzure {
    if ($SkipAuthentication) {
        Write-StatusMessage "Skipping authentication" -Type Warning
        return
    }
    
    Write-StatusMessage "Authenticating to Azure..." -Type Info
    
    try {
        $context = Get-AzContext
        if ($context) {
            Write-StatusMessage "✓ Already connected as $($context.Account.Id)" -Type Success
        }
        else {
            Connect-AzAccount | Out-Null
            $context = Get-AzContext
            Write-StatusMessage "✓ Connected to Azure as $($context.Account.Id)" -Type Success
        }
    }
    catch {
        Write-StatusMessage "Failed to connect to Azure: $_" -Type Error
    }
}

function Connect-ToGraph {
    if ($SkipAuthentication) {
        Write-StatusMessage "Skipping Graph authentication" -Type Warning
        return
    }
    
    Write-StatusMessage "Authenticating to Microsoft Graph..." -Type Info
    
    try {
        $context = Get-MgContext
        if ($context) {
            Write-StatusMessage "✓ Already connected as $($context.Account)" -Type Success
        }
        else {
            Connect-MgGraph -Scopes 'User.ReadWrite.All' | Out-Null
            $context = Get-MgContext
            Write-StatusMessage "✓ Connected to Microsoft Graph as $($context.Account)" -Type Success
        }
    }
    catch {
        Write-StatusMessage "Failed to connect to Microsoft Graph: $_" -Type Error
    }
}

function Show-NextSteps {
    param([string]$ProjectRoot)
    
    Write-StatusMessage "`n===== Next Steps =====" -Type Info
    
    Write-Host "`n1. " -NoNewline -ForegroundColor Yellow
    Write-Host "Update local.settings.json with your values:" -ForegroundColor White
    Write-Host "   code local.settings.json" -ForegroundColor Gray
    
    Write-Host "`n2. " -NoNewline -ForegroundColor Yellow
    Write-Host "Run tests to verify setup:" -ForegroundColor White
    Write-Host "   Invoke-Pester -Path ./tests" -ForegroundColor Gray
    
    Write-Host "`n3. " -NoNewline -ForegroundColor Yellow
    Write-Host "Start the function locally:" -ForegroundColor White
    Write-Host "   func start" -ForegroundColor Gray
    
    Write-Host "`n4. " -NoNewline -ForegroundColor Yellow
    Write-Host "Test the local endpoint:" -ForegroundColor White
    Write-Host "   curl -X POST http://localhost:7071/api/ResetUserPassword \" -ForegroundColor Gray
    Write-Host "     -H 'Authorization: Bearer YOUR_JWT_TOKEN' \" -ForegroundColor Gray
    Write-Host "     -H 'Content-Type: application/json' \" -ForegroundColor Gray
    Write-Host "     -d '{\"userId\":\"user@domain.com\"}'" -ForegroundColor Gray
    
    Write-Host "`n5. " -NoNewline -ForegroundColor Yellow
    Write-Host "Deploy to Azure when ready:" -ForegroundColor White
    Write-Host "   ./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName rg-pwdreset-dev" -ForegroundColor Gray
    Write-Host "   ./scripts/Deploy-FunctionApp.ps1 -FunctionAppName YOUR_FUNCTION_APP_NAME" -ForegroundColor Gray
    
    Write-StatusMessage "`n=====================`n" -Type Info
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Local Development Environment Setup =====" -Type Info
    
    $projectRoot = Split-Path -Parent $PSScriptRoot
    Write-StatusMessage "Project Root: $projectRoot`n" -Type Info
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-StatusMessage "Please install missing prerequisites and run again." -Type Error
        exit 1
    }
    
    # Install modules
    Install-RequiredModules
    
    # Create local.settings.json
    New-LocalSettingsFile -ProjectRoot $projectRoot -TenantId $TenantId -AppIdUri $AppIdUri
    
    # Authenticate
    Connect-ToAzure
    Connect-ToGraph
    
    # Show next steps
    Show-NextSteps -ProjectRoot $projectRoot
    
    Write-StatusMessage "Setup complete! You're ready to develop. 🚀" -Type Success
}
catch {
    Write-StatusMessage "Setup failed: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
