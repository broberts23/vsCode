#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$Location = 'centralindia',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ParametersFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/parameters.dev.bicepparam')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AzCliPresent {
    [CmdletBinding()]
    param()

    $az = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if ($null -eq $az) {
        throw "Azure CLI ('az') not found. Install Azure CLI and run 'az login' first. See https://learn.microsoft.com/cli/azure/install-azure-cli"
    }
}

function Assert-AzLogin {
    [CmdletBinding()]
    param()

    $raw = & az account show --only-show-errors 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Not logged into Azure CLI. Run 'az login' first. Details: $raw"
    }
}

function Get-NameFromResourceId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceId
    )

    $segments = $ResourceId.Trim('/') -split '/'
    if ($segments.Length -lt 1) {
        return $null
    }

    return $segments[-1]
}

Assert-AzCliPresent
Assert-AzLogin

Write-Verbose "Deploying infra to RG '$ResourceGroupName' in subscription '$SubscriptionId'"
Write-Verbose "Parameters: $ParametersFile"

if (-not (Test-Path -Path $ParametersFile -PathType Leaf)) {
    throw "Parameters file not found: $ParametersFile"
}

& az account set --subscription $SubscriptionId --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to set Azure subscription context to '$SubscriptionId'."
}

Write-Verbose "Ensuring resource group exists: $ResourceGroupName ($Location)"
& az group create --name $ResourceGroupName --location $Location --only-show-errors | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create/ensure resource group '$ResourceGroupName'."
}

$templateFile = (Join-Path -Path $PSScriptRoot -ChildPath '../infra/main.bicep')
if (-not (Test-Path -Path $templateFile -PathType Leaf)) {
    throw "Bicep template not found: $templateFile"
}

$deploymentName = "eg-partnercfg-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Verbose "Starting deployment: $deploymentName"

$args = @(
    'deployment', 'group', 'create',
    '--name', $deploymentName,
    '--resource-group', $ResourceGroupName,
    '--template-file', $templateFile,
    '--parameters', $ParametersFile,
    '--only-show-errors',
    '--query', 'properties.outputs',
    '-o', 'json'
)

$stderrFile = New-TemporaryFile
try {
    $raw = & az @args 2> $stderrFile
    $stderr = Get-Content -Path $stderrFile -Raw
}
finally {
    Remove-Item -Path $stderrFile -Force -ErrorAction SilentlyContinue
}

if ($LASTEXITCODE -ne 0) {
    $details = if (-not [string]::IsNullOrWhiteSpace($stderr)) { $stderr } else { ($raw -join "`n") }
    throw "Deployment failed: $details"
}

$rawText = if ($raw -is [System.Array]) { ($raw -join "`n") } else { [string]$raw }
$rawText = $rawText.Trim()
if ([string]::IsNullOrWhiteSpace($rawText)) {
    throw "Deployment succeeded but produced no JSON outputs. stderr: $stderr"
}

try {
    $outputs = $rawText | ConvertFrom-Json -Depth 64
}
catch {
    # Fallback: attempt to extract the JSON object if extra text leaked into stdout.
    $start = $rawText.IndexOf('{')
    $end = $rawText.LastIndexOf('}')
    if ($start -ge 0 -and $end -gt $start) {
        $jsonOnly = $rawText.Substring($start, $end - $start + 1)
        $outputs = $jsonOnly | ConvertFrom-Json -Depth 64
    }
    else {
        throw
    }
}

$functionAppId = $outputs.functionAppId.value
$functionResourceId = $outputs.functionResourceIdOut.value
$partnerConfigurationId = $outputs.partnerConfigurationId.value

[pscustomobject]@{
    deploymentName         = $deploymentName
    resourceGroupName      = $ResourceGroupName
    location               = $Location
    partnerConfigurationId = $partnerConfigurationId
    functionAppId          = $functionAppId
    functionAppName        = (Get-NameFromResourceId -ResourceId $functionAppId)
    functionResourceId     = $functionResourceId
    functionName           = (Get-NameFromResourceId -ResourceId $functionResourceId)
}
