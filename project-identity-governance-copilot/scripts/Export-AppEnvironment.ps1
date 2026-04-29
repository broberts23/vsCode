#!/usr/bin/env pwsh
#Requires -Version 7.4

# Read the latest deployment outputs for this resource group and print the environment variables
# required by the Python app in a copy-paste friendly format.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$DeploymentName,

    [Parameter()]
    [ValidateSet('PowerShell', 'Bash', 'Both')]
    [string]$Format = 'Both',

    [Parameter()]
    [string]$SearchIndexName = 'identity-governance-documents',

    [Parameter()]
    [string]$DatasetPack = 'seed',

    [Parameter()]
    [string]$DatasetRoot = (Join-Path $PSScriptRoot '..\..\shared\identity_seed\datasets')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-AzCliJson {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,

        [Parameter(Mandatory)]
        [string]$FailureMessage
    )

    $output = & az @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }

    return $output | ConvertFrom-Json
}

function Quote-BashValue {
    param([Parameter(Mandatory)][string]$Value)

    $singleQuoteEscape = "'" + '"' + "'" + '"' + "'"
    $escapedValue = $Value.Replace("'", $singleQuoteEscape)
    return "'{0}'" -f $escapedValue
}

function Write-EnvironmentBlock {
    param(
        [Parameter(Mandatory)]
        [string]$Shell,

        [Parameter(Mandatory)]
        [hashtable]$Variables
    )

    Write-Host ""
    Write-Host "$Shell commands:"

    foreach ($name in $Variables.Keys | Sort-Object) {
        $value = [string]$Variables[$name]

        if ($Shell -eq 'PowerShell') {
            Write-Host ('$env:{0} = "{1}"' -f $name, ($value -replace '"', '`"'))
        }
        else {
            Write-Host ('export {0}={1}' -f $name, (Quote-BashValue -Value $value))
        }
    }
}

$resolvedDatasetRoot = (Resolve-Path $DatasetRoot).Path

$deployment = if ($DeploymentName) {
    Invoke-AzCliJson -Arguments @(
        'deployment', 'group', 'show',
        '--resource-group', $ResourceGroupName,
        '--name', $DeploymentName,
        '--output', 'json'
    ) -FailureMessage 'Azure CLI failed while reading the named deployment. Run az login and confirm the deployment name.'
}
else {
    $history = Invoke-AzCliJson -Arguments @(
        'deployment', 'group', 'list',
        '--resource-group', $ResourceGroupName,
        '--query', '[0]',
        '--output', 'json'
    ) -FailureMessage 'Azure CLI failed while listing deployments for the resource group. Run az login and confirm the resource group.'

    if (-not $history) {
        throw 'No deployments were found for the resource group.'
    }

    Invoke-AzCliJson -Arguments @(
        'deployment', 'group', 'show',
        '--resource-group', $ResourceGroupName,
        '--name', $history.name,
        '--output', 'json'
    ) -FailureMessage 'Azure CLI failed while reading the latest deployment outputs.'
}

$outputs = $deployment.properties.outputs
if (-not $outputs) {
    throw 'The deployment did not return any outputs.'
}

$variables = [ordered]@{
    AZURE_OPENAI_CHAT_DEPLOYMENT = [string]$outputs.openAiChatDeploymentName.value
    AZURE_OPENAI_ENDPOINT        = [string]$outputs.openAiEndpoint.value
    AZURE_SEARCH_ENDPOINT        = [string]$outputs.searchEndpoint.value
    AZURE_SEARCH_INDEX_NAME      = $SearchIndexName
    IDENTITY_DATASET_PACK        = $DatasetPack
    IDENTITY_DATASET_ROOT        = $resolvedDatasetRoot
}

if ($Format -in @('PowerShell', 'Both')) {
    Write-EnvironmentBlock -Shell 'PowerShell' -Variables $variables
}

if ($Format -in @('Bash', 'Both')) {
    Write-EnvironmentBlock -Shell 'Bash' -Variables $variables
}