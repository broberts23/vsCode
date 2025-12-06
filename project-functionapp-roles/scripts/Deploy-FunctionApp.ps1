#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Deploys the Function App code to Azure.

.DESCRIPTION
    This script publishes the PowerShell Function App code to Azure Functions.
    It can deploy from a local directory or a zip package.

.PARAMETER FunctionAppName
    The name of the Function App to deploy to.

.PARAMETER ResourceGroupName
    The resource group containing the Function App. Optional if FunctionAppName is unique.

.PARAMETER SourcePath
    Path to the function app source code. Default is the project root.

.PARAMETER ZipDeploy
    Use zip deployment instead of regular deployment.

.PARAMETER RunTests
    Run Pester tests before deploying. Default is true.

.EXAMPLE
    ./Deploy-FunctionApp.ps1 -FunctionAppName pwdreset-func-dev-abc123

.EXAMPLE
    ./Deploy-FunctionApp.ps1 -FunctionAppName pwdreset-func-dev-abc123 -ResourceGroupName rg-pwdreset-dev -ZipDeploy

.LINK
    https://learn.microsoft.com/azure/azure-functions/functions-run-local
    https://learn.microsoft.com/azure/azure-functions/deployment-zip-push
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$FunctionAppName,

    [Parameter()]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$SourcePath,

    [Parameter()]
    [switch]$ZipDeploy,

    [Parameter()]
    [bool]$RunTests = $true,
    
    [Parameter()]
    [string]$KeyVaultUri,
    
    [Parameter()]
    [string]$DomainControllerFqdn,
    
    [Parameter()]
    [string]$DomainName,
    
    [Parameter()]
    [switch]$UpdateSettings
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

function Test-AzureConnection {
    try {
        $context = Get-AzContext
        if (-not $context) {
            throw 'Not connected to Azure'
        }
        Write-StatusMessage "Connected to Azure as: $($context.Account.Id)" -Type Success
        return $true
    }
    catch {
        Write-StatusMessage 'Not connected to Azure. Please run Connect-AzAccount first.' -Type Error
        return $false
    }
}

function Test-FunctionApp {
    param(
        [string]$Name,
        [string]$ResourceGroup
    )
    
    Write-StatusMessage "Verifying Function App exists: $Name" -Type Info
    
    if ($ResourceGroup) {
        $app = Get-AzFunctionApp -Name $Name -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
    }
    else {
        $app = Get-AzFunctionApp -Name $Name -ErrorAction SilentlyContinue
    }
    
    if (-not $app) {
        throw "Function App not found: $Name"
    }
    
    Write-StatusMessage "Function App found: $($app.Name) in $($app.ResourceGroup)" -Type Success
    return $app
}

function Update-FunctionAppSettings {
    <#
    .SYNOPSIS
        Updates Function App application settings
    .DESCRIPTION
        Configures required environment variables for LDAPS password reset functionality
    .PARAMETER FunctionAppName
        Name of the Function App
    .PARAMETER ResourceGroupName
        Resource group containing the Function App
    .PARAMETER KeyVaultUri
        Key Vault URI for secret access
    .PARAMETER DomainControllerFqdn
        Domain controller FQDN
    .PARAMETER DomainName
        Active Directory domain name
    .LINK
        https://learn.microsoft.com/powershell/module/az.functions/update-azfunctionappsetting?view=azps-latest
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FunctionAppName,
        
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory)]
        [string]$KeyVaultUri,
        
        [Parameter(Mandatory)]
        [string]$DomainControllerFqdn,
        
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    
    Write-StatusMessage "Updating Function App settings for LDAPS configuration..." -Type Info
    
    try {
        # Get current app settings
        $currentSettings = Get-AzFunctionAppSetting -Name $FunctionAppName -ResourceGroupName $ResourceGroupName
        
        # Prepare new settings (merge with existing)
        $newSettings = @{
            'KEY_VAULT_URI'          = $KeyVaultUri
            'DOMAIN_CONTROLLER_FQDN' = $DomainControllerFqdn
            'DOMAIN_NAME'            = $DomainName
        }
        
        # Merge with existing settings (preserve existing values)
        foreach ($key in $currentSettings.Keys) {
            if (-not $newSettings.ContainsKey($key)) {
                $newSettings[$key] = $currentSettings[$key]
            }
        }
        
        # Update Function App settings
        Update-AzFunctionAppSetting `
            -Name $FunctionAppName `
            -ResourceGroupName $ResourceGroupName `
            -AppSetting $newSettings `
            -Force `
            -ErrorAction Stop
        
        Write-StatusMessage "Function App settings updated successfully" -Type Success
        Write-StatusMessage "  KEY_VAULT_URI: $KeyVaultUri" -Type Info
        Write-StatusMessage "  DOMAIN_CONTROLLER_FQDN: $DomainControllerFqdn" -Type Info
        Write-StatusMessage "  DOMAIN_NAME: $DomainName" -Type Info
    }
    catch {
        Write-StatusMessage "Failed to update Function App settings: $_" -Type Error
        throw
    }
}

function Invoke-PesterTests {
    param([string]$ProjectRoot)
    
    Write-StatusMessage "Running Pester tests..." -Type Info
    
    $testsPath = Join-Path $ProjectRoot 'tests'
    if (-not (Test-Path $testsPath)) {
        Write-StatusMessage "No tests directory found. Skipping tests." -Type Warning
        return $true
    }
    
    $config = New-PesterConfiguration
    $config.Run.Path = $testsPath
    $config.Run.PassThru = $true
    $config.Output.Verbosity = 'Detailed'
    $config.CodeCoverage.Enabled = $false
    
    $result = Invoke-Pester -Configuration $config
    
    if ($result.FailedCount -gt 0) {
        Write-StatusMessage "Tests failed: $($result.FailedCount) of $($result.TotalCount)" -Type Error
        return $false
    }
    
    Write-StatusMessage "All tests passed: $($result.PassedCount) of $($result.TotalCount)" -Type Success
    return $true
}

function New-DeploymentPackage {
    param(
        [string]$SourcePath,
        [string]$OutputPath
    )
    
    Write-StatusMessage "Creating deployment package..." -Type Info
    
    # Verify source path exists
    if (-not (Test-Path $SourcePath)) {
        throw "Source path not found: $SourcePath"
    }
    
    # Get all items in the FunctionApp directory
    $items = Get-ChildItem -Path $SourcePath -Force
    
    if ($items.Count -eq 0) {
        throw "FunctionApp directory is empty: $SourcePath"
    }
    
    Write-StatusMessage "Creating zip archive from FunctionApp directory..." -Type Info
    Write-StatusMessage "  Contents to include:" -Type Info
    foreach ($item in $items) {
        Write-StatusMessage "    - $($item.Name)" -Type Info
    }
    
    # Remove existing zip if it exists
    if (Test-Path $OutputPath) {
        Remove-Item -Path $OutputPath -Force
    }
    
    # Create zip with all items at the root level
    # PowerShell 7.4+ supports multiple paths in Compress-Archive
    $itemPaths = $items | Select-Object -ExpandProperty FullName
    Compress-Archive -Path $itemPaths -DestinationPath $OutputPath -CompressionLevel Optimal
    
    if (-not (Test-Path $OutputPath)) {
        throw "Failed to create deployment package at: $OutputPath"
    }
    
    Write-StatusMessage "Deployment package created: $OutputPath ($('{0:N0}' -f (Get-Item $OutputPath).Length) bytes)" -Type Success
    return $OutputPath
}

function Publish-FunctionAppCode {
    param(
        [string]$FunctionAppName,
        [string]$ResourceGroupName,
        [string]$SourcePath,
        [bool]$UseZip
    )
    
    if ($UseZip) {
        Write-StatusMessage "Using zip deployment..." -Type Info
        
        # Check if Azure CLI is installed
        $azPath = Get-Command 'az' -ErrorAction SilentlyContinue
        if (-not $azPath) {
            throw "Azure CLI not found. Install from: https://learn.microsoft.com/cli/azure/install-azure-cli"
        }
        
        $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-deploy-$(Get-Date -Format 'yyyyMMddHHmmss').zip"
        
        try {
            $zipFile = New-DeploymentPackage -SourcePath $SourcePath -OutputPath $zipPath
            
            if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Deploy Function App via zip')) {
                Write-StatusMessage "Publishing to Azure..." -Type Info
                Write-StatusMessage "  Function App: $FunctionAppName" -Type Info
                if ($ResourceGroupName) {
                    Write-StatusMessage "  Resource Group: $ResourceGroupName" -Type Info
                }
                Write-StatusMessage "  Zip File: $zipFile ($('{0:N0}' -f (Get-Item $zipFile).Length) bytes)" -Type Info
                
                # Use Azure CLI for deployment
                $azCommand = @(
                    'functionapp', 'deployment', 'source', 'config-zip',
                    '--resource-group', $ResourceGroupName,
                    '--name', $FunctionAppName,
                    '--src', $zipFile
                )
                
                Write-StatusMessage "Executing: az $($azCommand -join ' ')" -Type Info
                $output = az @azCommand 2>&1
                $exitCode = $LASTEXITCODE
                
                if ($exitCode -ne 0) {
                    throw "Deployment failed with exit code: $exitCode`n$output"
                }
                
                Write-StatusMessage "Deployment completed successfully!" -Type Success
            }
        }
        catch {
            Write-StatusMessage "Deployment failed: $_" -Type Error
            
            # Provide diagnostic information
            Write-StatusMessage "`nDiagnostic Information:" -Type Warning
            Write-StatusMessage "  Function App Name: $FunctionAppName" -Type Info
            Write-StatusMessage "  Resource Group: $ResourceGroupName" -Type Info
            
            # Check if the Function App exists
            try {
                $showOutput = az functionapp show --name $FunctionAppName --resource-group $ResourceGroupName 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-StatusMessage "  ✓ Function App exists" -Type Success
                }
                else {
                    Write-StatusMessage "  ✗ Function App NOT found - verify the name and resource group" -Type Error
                }
            }
            catch {
                Write-StatusMessage "  Could not verify Function App existence" -Type Warning
            }
            
            # Check Azure subscription context
            try {
                $accountOutput = az account show --query "[name,id]" -o tsv 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $parts = $accountOutput -split '\t'
                    Write-StatusMessage "  Current Subscription: $($parts[0]) ($($parts[1]))" -Type Info
                }
            }
            catch {
                Write-StatusMessage "  Could not determine current subscription" -Type Warning
            }
            
            throw
        }
        finally {
            if (Test-Path $zipPath) {
                Remove-Item -Path $zipPath -Force
            }
        }
    }
    else {
        Write-StatusMessage "Using func tools deployment..." -Type Info
        
        # Check if func tools is installed
        $funcPath = Get-Command 'func' -ErrorAction SilentlyContinue
        if (-not $funcPath) {
            throw "Azure Functions Core Tools not found. Install from: https://learn.microsoft.com/azure/azure-functions/functions-run-local"
        }
        
        if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Deploy Function App via func tools')) {
            Write-StatusMessage "Publishing to Azure..." -Type Info
            
            Push-Location $SourcePath
            try {
                $output = func azure functionapp publish $FunctionAppName --powershell 2>&1
                
                if ($LASTEXITCODE -ne 0) {
                    throw "Deployment failed with exit code: $LASTEXITCODE`n$output"
                }
                
                Write-StatusMessage "Deployment completed successfully!" -Type Success
            }
            finally {
                Pop-Location
            }
        }
    }
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Deploy Password Reset Function App =====" -Type Info
    Write-StatusMessage "Function App: $FunctionAppName`n" -Type Info
    
    # Determine source path
    if (-not $SourcePath) {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $SourcePath = Join-Path $projectRoot 'FunctionApp'
    }
    
    Write-StatusMessage "Source Path: $SourcePath" -Type Info
    
    # Check Azure connection
    if (-not (Test-AzureConnection)) {
        throw 'Not connected to Azure'
    }
    
    # Verify Function App exists
    $app = Test-FunctionApp -Name $FunctionAppName -ResourceGroup $ResourceGroupName
    
    # Run tests
    if ($RunTests) {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $testsPass = Invoke-PesterTests -ProjectRoot $projectRoot
        if (-not $testsPass) {
            throw 'Tests failed. Deployment aborted.'
        }
    }
    else {
        Write-StatusMessage "Skipping tests (RunTests=false)" -Type Warning
    }
    
    # Deploy
    Publish-FunctionAppCode `
        -FunctionAppName $FunctionAppName `
        -ResourceGroupName $ResourceGroupName `
        -SourcePath $SourcePath `
        -UseZip:$ZipDeploy
    
    # Update Function App settings (if parameters provided)
    if ($UpdateSettings -and $KeyVaultUri -and $DomainControllerFqdn -and $DomainName) {
        Update-FunctionAppSettings `
            -FunctionAppName $FunctionAppName `
            -ResourceGroupName $ResourceGroupName `
            -KeyVaultUri $KeyVaultUri `
            -DomainControllerFqdn $DomainControllerFqdn `
            -DomainName $DomainName
    }
    elseif ($UpdateSettings) {
        Write-StatusMessage "UpdateSettings specified but missing required parameters (KeyVaultUri, DomainControllerFqdn, DomainName)" -Type Warning
    }
    
    Write-StatusMessage "`nDeployment process completed!" -Type Success
    Write-StatusMessage "Function App URL: https://$($app.DefaultHostName)/api/ResetUserPassword" -Type Info
}
catch {
    Write-StatusMessage "Deployment failed: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
