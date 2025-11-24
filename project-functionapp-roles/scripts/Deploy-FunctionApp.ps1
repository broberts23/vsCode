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
    [bool]$RunTests = $true
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
    
    # Exclude test files and other unnecessary items
    $excludePatterns = @(
        '*.Tests.ps1'
        'tests/*'
        '.git/*'
        '.vscode/*'
        'infra/*'
        'scripts/*'
        '.gitignore'
        '.funcignore'
        'README.md'
    )
    
    # Create temp directory for packaging
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-$(New-Guid)"
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    
    try {
        # Copy files
        Write-StatusMessage "Copying files to temp directory..." -Type Info
        $itemsToCopy = @(
            'host.json'
            'profile.ps1'
            'requirements.psd1'
            'Modules'
            'ResetUserPassword'
        )
        
        foreach ($item in $itemsToCopy) {
            $sourcePath = Join-Path $SourcePath $item
            if (Test-Path $sourcePath) {
                $destPath = Join-Path $tempDir $item
                Copy-Item -Path $sourcePath -Destination $destPath -Recurse -Force
                Write-Verbose "Copied: $item"
            }
        }
        
        # Create zip
        Write-StatusMessage "Creating zip archive..." -Type Info
        Compress-Archive -Path "$tempDir/*" -DestinationPath $OutputPath -Force
        
        Write-StatusMessage "Deployment package created: $OutputPath" -Type Success
        return $OutputPath
    }
    finally {
        # Cleanup temp directory
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
    }
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
        
        $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "funcapp-deploy-$(Get-Date -Format 'yyyyMMddHHmmss').zip"
        
        try {
            $zipFile = New-DeploymentPackage -SourcePath $SourcePath -OutputPath $zipPath
            
            if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Deploy Function App via zip')) {
                Write-StatusMessage "Publishing to Azure..." -Type Info
                
                Publish-AzWebApp `
                    -ResourceGroupName $ResourceGroupName `
                    -Name $FunctionAppName `
                    -ArchivePath $zipFile `
                    -Force `
                    -ErrorAction Stop
                
                Write-StatusMessage "Deployment completed successfully!" -Type Success
            }
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
        $scriptRoot = Split-Path -Parent $PSScriptRoot
        $SourcePath = $scriptRoot
    }
    
    Write-StatusMessage "Source Path: $SourcePath" -Type Info
    
    # Check Azure connection
    if (-not (Test-AzureConnection)) {
        throw 'Not connected to Azure'
    }
    
    # Verify Function App exists
    $app = Test-FunctionApp -Name $FunctionAppName -ResourceGroup $ResourceGroupName
    if (-not $ResourceGroupName) {
        $ResourceGroupName = $app.ResourceGroup
    }
    
    # Run tests
    if ($RunTests) {
        $testsPass = Invoke-PesterTests -ProjectRoot $SourcePath
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
    
    Write-StatusMessage "`nDeployment process completed!" -Type Success
    Write-StatusMessage "Function App URL: https://$($app.DefaultHostName)/api/ResetUserPassword" -Type Info
}
catch {
    Write-StatusMessage "Deployment failed: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
