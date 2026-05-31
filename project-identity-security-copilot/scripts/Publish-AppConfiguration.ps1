#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true)]
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
    [string]$SearchIndexName = 'identity-security-knowledge',

    [Parameter()]
    [string]$Prefix = 'IdentitySecurityCopilot',

    [Parameter()]
    [string]$Label
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Status {
    param([Parameter(Mandatory)][string]$Message)
    Write-Information $Message -InformationAction Continue
}

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

function Set-AppConfigurationKeyValue {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter(Mandatory)]
        [string]$Key,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter()]
        [string]$AssignedLabel
    )

    $arguments = @(
        'appconfig', 'kv', 'set',
        '--endpoint', $Endpoint,
        '--key', $Key,
        '--value', $Value,
        '--yes',
        '--auth-mode', 'login',
        '--output', 'none'
    )

    if ($AssignedLabel) {
        $arguments += @('--label', $AssignedLabel)
    }

    Invoke-AzCli -Arguments $arguments -FailureMessage "Azure CLI failed while setting App Configuration key '$Key'."
}

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

$appConfigurationEndpoint = [string]$outputs.appConfigEndpoint.value
if (-not $appConfigurationEndpoint) {
    throw 'The deployment outputs did not include an App Configuration endpoint.'
}

$keyValues = [ordered]@{
    "$Prefix`:Foundry:ProjectEndpoint"              = $FoundryProjectEndpoint
    "$Prefix`:Foundry:ChatDeployment"              = $ChatDeployment
    "$Prefix`:Foundry:SummaryDeployment"           = $SummaryDeployment
    "$Prefix`:Search:Endpoint"                     = [string]$outputs.searchEndpoint.value
    "$Prefix`:Search:IndexName"                    = $SearchIndexName
    "$Prefix`:Security:KeyVaultUri"                = [string]$outputs.keyVaultUri.value
    "$Prefix`:Observability:AppInsightsConnection" = [string]$outputs.appInsightsConnectionString.value
    "$Prefix`:Identity:ManagedIdentityClientId"    = [string]$outputs.managedIdentityClientId.value
}

if ($PSCmdlet.ShouldProcess($appConfigurationEndpoint, 'Publish identity security copilot configuration')) {
    Write-Status 'Publishing centralized application settings to App Configuration.'

    foreach ($entry in $keyValues.GetEnumerator()) {
        Set-AppConfigurationKeyValue -Endpoint $appConfigurationEndpoint -Key $entry.Key -Value ([string]$entry.Value) -AssignedLabel $Label
    }

    Write-Status 'App Configuration publication completed.'
}