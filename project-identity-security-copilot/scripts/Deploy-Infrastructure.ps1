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
    [string]$ParameterFile = (Join-Path $PSScriptRoot '../infra/parameters.dev.json'),

    [Parameter()]
    [switch]$DeploymentWhatIf
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
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
$deploymentName = 'identity-security-copilot-{0}-{1}' -f $Environment, (Get-Date -Format 'yyyyMMddHHmmss')

Write-Status "Validating Azure CLI sign-in context."
Invoke-AzCli -Arguments @('account', 'show', '--output', 'none') -FailureMessage 'Azure CLI is not authenticated. Run az login first.'

$deploymentArguments = @(
    'deployment', 'group', 'create',
    '--name', $deploymentName,
    '--resource-group', $ResourceGroupName,
    '--template-file', $templateFile,
    '--parameters', $resolvedParameterFile,
    '--parameters', "deploymentEnvironment=$Environment",
    '--parameters', "location=$Location"
)

if ($DeploymentWhatIf) {
    Write-Status "Running what-if deployment for identity security copilot infrastructure."
    Invoke-AzCli -Arguments ($deploymentArguments[0..1] + @('what-if') + $deploymentArguments[3..($deploymentArguments.Length - 1)]) -FailureMessage 'Azure CLI what-if deployment failed.'
    return
}

if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy identity security copilot infrastructure')) {
    Write-Status "Deploying identity security copilot infrastructure."
    Invoke-AzCli -Arguments $deploymentArguments -FailureMessage 'Azure CLI deployment failed.'
    Write-Status "Deployment completed."
}
