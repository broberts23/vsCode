#!/usr/bin/env pwsh
#Requires -Version 7.4

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
    [string]$ParameterFile,

    [Parameter()]
    [switch]$WhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $color = switch ($Type) {
        'Info' { 'Cyan' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
    }

    Write-Host $Message -ForegroundColor $color
}

function Test-AzureConnection {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $context) {
        throw 'Not connected to Azure. Run Connect-AzAccount first.'
    }

    Write-Status "Connected to subscription: $($context.Subscription.Name)" -Type Success
}

function Ensure-ResourceGroup {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Region
    )

    $resourceGroup = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $resourceGroup) {
        Write-Status "Creating resource group $Name in $Region" -Type Info
        $resourceGroup = New-AzResourceGroup -Name $Name -Location $Region
    }

    return $resourceGroup
}

try {
    Test-AzureConnection

    $projectRoot = Split-Path -Parent $PSScriptRoot
    $infraRoot = Join-Path $projectRoot 'infra'
    $templateFile = Join-Path $infraRoot 'main.bicep'

    if ([string]::IsNullOrWhiteSpace($ParameterFile)) {
        $ParameterFile = Join-Path $infraRoot "parameters.$Environment.json"
    }

    if (-not (Test-Path -LiteralPath $templateFile)) {
        throw "Template file not found: $templateFile"
    }

    if (-not (Test-Path -LiteralPath $ParameterFile)) {
        throw "Parameter file not found: $ParameterFile"
    }

    Ensure-ResourceGroup -Name $ResourceGroupName -Region $Location | Out-Null

    $deploymentName = "agentvend-$Environment-$(Get-Date -Format 'yyyyMMddHHmmss')"
    $deploymentParameters = @{
        Name                  = $deploymentName
        ResourceGroupName     = $ResourceGroupName
        TemplateFile          = $templateFile
        TemplateParameterFile = $ParameterFile
        location              = $Location
    }

    if ($WhatIf) {
        Write-Status 'Running What-If deployment preview' -Type Info
        Get-AzResourceGroupDeploymentWhatIfResult @deploymentParameters | Out-Host
        return
    }

    if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy agent vending machine infrastructure')) {
        $deployment = New-AzResourceGroupDeployment @deploymentParameters
        if ($deployment.ProvisioningState -ne 'Succeeded') {
            throw "Deployment failed with state $($deployment.ProvisioningState)"
        }

        Write-Status 'Infrastructure deployment completed successfully.' -Type Success
        Write-Host "Function App Name: $($deployment.Outputs.functionAppName.Value)"
        Write-Host "Function Hostname: $($deployment.Outputs.functionAppHostname.Value)"
        Write-Host "Managed Identity PrincipalId: $($deployment.Outputs.functionAppPrincipalId.Value)"
    }
}
catch {
    Write-Status $_.Exception.Message -Type Error
    throw
}