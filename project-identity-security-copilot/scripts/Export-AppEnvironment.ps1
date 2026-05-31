#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$FoundryProjectEndpoint,

    [Parameter(Mandatory)]
    [string]$ChatDeployment,

    [Parameter()]
    [string]$SummaryDeployment,

    [Parameter()]
    [string]$DeploymentName,

    [Parameter()]
    [ValidateSet('PowerShell', 'Bash', 'Both')]
    [string]$Format = 'Both',

    [Parameter()]
    [string]$SearchIndexName = 'identity-security-knowledge',

    [Parameter()]
    [string]$KnowledgeRoot = (Join-Path $PSScriptRoot '..\knowledge')
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

function ConvertTo-BashQuotedValue {
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

    Write-Host ''
    Write-Host "$Shell commands:"

    foreach ($name in $Variables.Keys | Sort-Object) {
        $value = [string]$Variables[$name]

        if ($Shell -eq 'PowerShell') {
            Write-Host ('$env:' + $name + ' = "' + ($value -replace '"', '`"') + '"')
        }
        else {
            Write-Host ('export ' + $name + '=' + (ConvertTo-BashQuotedValue -Value $value))
        }
    }
}

$resolvedKnowledgeRoot = (Resolve-Path $KnowledgeRoot).Path
if (-not $SummaryDeployment) {
    $SummaryDeployment = $ChatDeployment
}

$deployment = if ($DeploymentName) {
    Invoke-AzCliJson -Arguments @(
        'deployment', 'group', 'show',
        '--resource-group', $ResourceGroupName,
        '--name', $DeploymentName,
        '--output', 'json'
    ) -FailureMessage 'Azure CLI failed while reading the named deployment.'
}
else {
    $history = Invoke-AzCliJson -Arguments @(
        'deployment', 'group', 'list',
        '--resource-group', $ResourceGroupName,
        '--query', '[0]',
        '--output', 'json'
    ) -FailureMessage 'Azure CLI failed while listing deployments.'

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
    AZURE_AI_CHAT_DEPLOYMENT    = $ChatDeployment
    AZURE_AI_PROJECT_ENDPOINT   = $FoundryProjectEndpoint
    AZURE_AI_SUMMARY_DEPLOYMENT = $SummaryDeployment
    AZURE_SEARCH_ENDPOINT       = [string]$outputs.searchEndpoint.value
    AZURE_SEARCH_INDEX_NAME     = $SearchIndexName
    KNOWLEDGE_ROOT              = $resolvedKnowledgeRoot
}

if ($outputs.PSObject.Properties.Name -contains 'appConfigEndpoint') {
    $variables['AZURE_APP_CONFIGURATION_ENDPOINT'] = [string]$outputs.appConfigEndpoint.value
}

if ($outputs.PSObject.Properties.Name -contains 'keyVaultUri') {
    $variables['AZURE_KEY_VAULT_URI'] = [string]$outputs.keyVaultUri.value
}

if ($outputs.PSObject.Properties.Name -contains 'appInsightsConnectionString') {
    $variables['APPLICATIONINSIGHTS_CONNECTION_STRING'] = [string]$outputs.appInsightsConnectionString.value
}

if ($outputs.PSObject.Properties.Name -contains 'managedIdentityClientId') {
    $variables['AZURE_CLIENT_ID'] = [string]$outputs.managedIdentityClientId.value
}

if ($Format -in @('PowerShell', 'Both')) {
    Write-EnvironmentBlock -Shell 'PowerShell' -Variables $variables
}

if ($Format -in @('Bash', 'Both')) {
    Write-EnvironmentBlock -Shell 'Bash' -Variables $variables
}
