#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('dev', 'test', 'prod')]
    [string]$Environment,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Location = 'eastus',

    [Parameter()]
    [string]$ParameterFile,

    [Parameter()]
    [hashtable]$ParameterOverrides,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
$infraPath = Join-Path $projectRoot 'infra'
$templateFile = Join-Path $infraPath 'main.bicep'

if (-not $ParameterFile) {
    $ParameterFile = Join-Path $infraPath "parameters.$Environment.json"
}

if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
    throw 'Connect-AzAccount before running this script.'
}

if (-not (Test-Path $templateFile)) {
    throw "Template file not found: $templateFile"
}

if (-not (Test-Path $ParameterFile)) {
    throw "Parameter file not found: $ParameterFile"
}

$resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $resourceGroup) {
    $resourceGroup = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
}

$deploymentName = "legacyjump-$Environment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy infrastructure')) {
    $deploymentParameters = @{
        Name = $deploymentName
        ResourceGroupName = $ResourceGroupName
        TemplateFile = $templateFile
        TemplateParameterFile = $ParameterFile
        Verbose = $VerbosePreference
    }

    if ($ParameterOverrides -and $ParameterOverrides.Count -gt 0) {
        $deploymentParameters.TemplateParameterObject = $ParameterOverrides
    }

    $deployment = New-AzResourceGroupDeployment @deploymentParameters

    if ($deployment.ProvisioningState -ne 'Succeeded') {
        throw "Deployment failed with state '$($deployment.ProvisioningState)'."
    }

    $deployment.Outputs.GetEnumerator() | Sort-Object Key | ForEach-Object {
        Write-Information ("{0}: {1}" -f $_.Key, $_.Value.Value) -InformationAction Continue
    }

    if ($PassThru) {
        return $deployment
    }
}