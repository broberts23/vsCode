#!/usr/bin/env pwsh
#Requires -Version 7.4

# This script is the deployment entry point, similar to a repo-level wrapper around `New-AzResourceGroupDeployment`.

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
    [string]$ParameterFile = (Join-Path $PSScriptRoot '../infra/parameters.dev.json'),

    [Parameter()]
    [switch]$DeploymentWhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    # Tiny wrapper so deployment progress goes through the Information stream consistently.
    param([Parameter(Mandatory)][string]$Message)
    Write-Information $Message -InformationAction Continue
}

function Invoke-AzCli {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [string]$FailureMessage
    )

    & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

$templateFile = Join-Path $PSScriptRoot '../infra/main.bicep'
$resolvedParameterFile = (Resolve-Path $ParameterFile).Path

if (-not (Test-Path $templateFile)) {
    throw "Template file not found: $templateFile"
}

if (-not (Test-Path $ParameterFile)) {
    throw "Parameter file not found: $ParameterFile"
}

Write-Status "Ensuring resource group '$ResourceGroupName' exists in '$Location'."
Invoke-AzCli -Arguments @('group', 'create', '--name', $ResourceGroupName, '--location', $Location) -FailureMessage 'Azure CLI failed while ensuring the resource group exists. Run az login and confirm the target subscription.' | Out-Null

# Build the Azure CLI argument array incrementally so it is easy to inspect and adjust.
$deploymentArgs = @(
    'deployment', 'group', 'create',
    '--resource-group', $ResourceGroupName,
    '--template-file', $templateFile,
    '--name', ("idgovcopilot-{0}" -f $Environment),
    '--parameters', ("@{0}" -f $resolvedParameterFile),
    '--parameters', ("deploymentEnvironment={0}" -f $Environment),
    '--no-prompt'
)

if ($DeploymentWhatIf) {
    # Swap `create` for `what-if` in-place so the rest of the argument array stays identical.
    $deploymentArgs[2] = 'what-if'
}

Write-Status 'Running Bicep deployment.'
Invoke-AzCli -Arguments $deploymentArgs -FailureMessage 'Azure CLI failed while running the Bicep deployment. Check authentication, subscription context, and template parameters.'