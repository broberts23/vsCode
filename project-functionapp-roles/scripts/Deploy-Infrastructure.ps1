#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Deploys the Password Reset Function App infrastructure to Azure.

.DESCRIPTION
    This script deploys the Bicep template to create all required Azure resources
    for the Password Reset Function App, including:
    - Function App (PowerShell 7.4 on Linux)
    - App Service Plan (Consumption)
    - Storage Account
    - Key Vault
    - Application Insights
    - Log Analytics Workspace
    - Managed Identity with RBAC assignments

.PARAMETER Environment
    The environment to deploy to (dev, test, prod).

.PARAMETER ResourceGroupName
    The name of the resource group to deploy to. Will be created if it doesn't exist.

.PARAMETER Location
    The Azure region for the deployment. Default is 'eastus'.

.PARAMETER ParameterFile
    Path to the parameter file. If not specified, uses infra/parameters.<Environment>.json

.PARAMETER WhatIf
    Runs the deployment in What-If mode to preview changes without deploying.

.EXAMPLE
    ./Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName rg-pwdreset-dev

.EXAMPLE
    ./Deploy-Infrastructure.ps1 -Environment prod -ResourceGroupName rg-pwdreset-prod -WhatIf

.LINK
    https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-powershell
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('dev', 'test', 'prod')]
    [string]$Environment,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$Location = 'eastus',

    [Parameter()]
    [string]$ParameterFile
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
        Write-StatusMessage "Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))" -Type Info
        return $true
    }
    catch {
        Write-StatusMessage 'Not connected to Azure. Please run Connect-AzAccount first.' -Type Error
        return $false
    }
}

function New-ResourceGroupIfNotExists {
    param(
        [string]$Name,
        [string]$Location
    )
    
    $rg = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    if (-not $rg) {
        if ($PSCmdlet.ShouldProcess($Name, 'Create Resource Group')) {
            Write-StatusMessage "Creating resource group: $Name" -Type Info
            $rg = New-AzResourceGroup -Name $Name -Location $Location
            Write-StatusMessage "Resource group created successfully" -Type Success
        }
    }
    else {
        Write-StatusMessage "Resource group already exists: $Name" -Type Info
    }
    return $rg
}

function Invoke-BicepDeployment {
    param(
        [string]$ResourceGroupName,
        [string]$TemplateFile,
        [string]$ParameterFile
    )
    
    $deploymentName = "pwdreset-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    
    Write-StatusMessage "Starting deployment: $deploymentName" -Type Info
    Write-StatusMessage "Template: $TemplateFile" -Type Info
    Write-StatusMessage "Parameters: $ParameterFile" -Type Info
    
    $deploymentParams = @{
        Name                  = $deploymentName
        ResourceGroupName     = $ResourceGroupName
        TemplateFile          = $TemplateFile
        TemplateParameterFile = $ParameterFile
        Verbose               = $VerbosePreference
    }
    
    if ($WhatIfPreference) {
        Write-StatusMessage 'Running What-If analysis...' -Type Info
        $result = Get-AzResourceGroupDeploymentWhatIfResult @deploymentParams
        return $result
    }
    
    if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy Bicep template')) {
        $deployment = New-AzResourceGroupDeployment @deploymentParams
        
        if ($deployment.ProvisioningState -eq 'Succeeded') {
            Write-StatusMessage 'Deployment completed successfully!' -Type Success
            return $deployment
        }
        else {
            Write-StatusMessage "Deployment failed with state: $($deployment.ProvisioningState)" -Type Error
            return $deployment
        }
    }
}

function Show-DeploymentOutputs {
    param($Deployment)
    
    if (-not $Deployment.Outputs) {
        return
    }
    
    Write-StatusMessage "`n===== Deployment Outputs =====" -Type Info
    foreach ($key in $Deployment.Outputs.Keys) {
        $value = $Deployment.Outputs[$key].Value
        Write-Host "  $key" -NoNewline -ForegroundColor Cyan
        Write-Host ": " -NoNewline
        Write-Host $value -ForegroundColor White
    }
    Write-StatusMessage "==============================`n" -Type Info
}

# ====================================
# Main Script
# ====================================

try {
    Write-StatusMessage "`n===== Password Reset Function App Deployment =====" -Type Info
    Write-StatusMessage "Environment: $Environment" -Type Info
    Write-StatusMessage "Resource Group: $ResourceGroupName" -Type Info
    Write-StatusMessage "Location: $Location`n" -Type Info
    
    # Check Azure connection
    if (-not (Test-AzureConnection)) {
        throw 'Not connected to Azure'
    }
    
    # Determine parameter file path
    $scriptRoot = Split-Path -Parent $PSScriptRoot
    $infraPath = Join-Path $scriptRoot 'infra'
    $templateFile = Join-Path $infraPath 'main.bicep'
    
    if (-not $ParameterFile) {
        $ParameterFile = Join-Path $infraPath "parameters.$Environment.json"
    }
    
    # Validate files exist
    if (-not (Test-Path $templateFile)) {
        throw "Template file not found: $templateFile"
    }
    
    if (-not (Test-Path $ParameterFile)) {
        throw "Parameter file not found: $ParameterFile"
    }
    
    # Create resource group
    $rg = New-ResourceGroupIfNotExists -Name $ResourceGroupName -Location $Location
    
    # Deploy Bicep template
    $deployment = Invoke-BicepDeployment `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile $templateFile `
        -ParameterFile $ParameterFile
    
    # Show outputs
    if ($deployment -and -not $WhatIfPreference) {
        Show-DeploymentOutputs -Deployment $deployment
        
        Write-StatusMessage "`nNext Steps:" -Type Info
        Write-Host "  1. Grant Microsoft Graph API permissions to the Function App Managed Identity" -ForegroundColor Yellow
        Write-Host "     - Run: " -NoNewline -ForegroundColor Yellow
        Write-Host "./scripts/Grant-GraphPermissions.ps1 -PrincipalId $($deployment.Outputs.functionAppPrincipalId.Value)" -ForegroundColor White
        Write-Host "`n  2. Configure Entra ID App Registration with Role.PasswordReset app role" -ForegroundColor Yellow
        Write-Host "     - Run: " -NoNewline -ForegroundColor Yellow
        Write-Host "./scripts/Configure-AppRegistration.ps1" -ForegroundColor White
        Write-Host "`n  3. Deploy the Function App code" -ForegroundColor Yellow
        Write-Host "     - Run: " -NoNewline -ForegroundColor Yellow
        Write-Host "./scripts/Deploy-FunctionApp.ps1 -FunctionAppName $($deployment.Outputs.functionAppName.Value)" -ForegroundColor White
    }
    
    Write-StatusMessage "`nDeployment process completed." -Type Success
}
catch {
    Write-StatusMessage "Deployment failed: $_" -Type Error
    Write-StatusMessage $_.ScriptStackTrace -Type Error
    exit 1
}
