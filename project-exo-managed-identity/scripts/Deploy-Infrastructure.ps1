#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Deploys the Exchange Online managed-identity Function App infrastructure via Azure CLI.

.PARAMETER Environment
    Target environment (dev, test, prod).

.PARAMETER ResourceGroupName
    Resource group to create or reuse.

.PARAMETER Location
    Azure region for the resource group and resources.

.PARAMETER ParameterFile
    Optional path to a Bicep parameter file. Defaults to infra/parameters.<Environment>.json.

.PARAMETER SubscriptionId
    Optional subscription to target. When omitted, uses the current az account.

.EXAMPLE
    ./Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName rg-exomi-dev
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
    [string]$ParameterFile,

    [Parameter()]
    [string]$SubscriptionId
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

    $account = $raw | ConvertFrom-Json -Depth 8
    Write-Status "Connected to subscription: $($account.name) ($($account.id))" -Type Success
}

function Invoke-AzJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments
    )

    $raw = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "az command failed: az $($Arguments -join ' ') :: $raw"
    }

    if ([string]::IsNullOrWhiteSpace(($raw | Out-String).Trim())) {
        return $null
    }

    return ($raw | ConvertFrom-Json -Depth 64)
}

function Initialize-ResourceGroup {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Region
    )

    $existing = & az group show --name $Name --only-show-errors -o json 2>&1
    if ($LASTEXITCODE -eq 0) {
        return ($existing | ConvertFrom-Json -Depth 8)
    }

    Write-Status "Creating resource group $Name in $Region" -Type Info
    return (Invoke-AzJson -Arguments @(
            'group', 'create',
            '--name', $Name,
            '--location', $Region,
            '--only-show-errors',
            '-o', 'json'
        ))
}

try {
    Assert-AzCliPresent
    Assert-AzLogin

    if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $null = Invoke-AzJson -Arguments @(
            'account', 'set',
            '--subscription', $SubscriptionId,
            '--only-show-errors'
        )
        Write-Status "Using subscription: $SubscriptionId" -Type Info
    }

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

    Initialize-ResourceGroup -Name $ResourceGroupName -Region $Location | Out-Null

    $deploymentName = "exomi-$Environment-$(Get-Date -Format 'yyyyMMddHHmmss')"

    if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Deploy Exchange Online managed-identity infrastructure')) {
        Write-Status "Starting deployment $deploymentName" -Type Info

        $deployment = Invoke-AzJson -Arguments @(
            'deployment', 'group', 'create',
            '--name', $deploymentName,
            '--resource-group', $ResourceGroupName,
            '--template-file', $templateFile,
            '--parameters', $ParameterFile,
            '--parameters', "location=$Location",
            '--only-show-errors',
            '-o', 'json'
        )

        $state = [string]$deployment.properties.provisioningState
        if ($state -ne 'Succeeded') {
            throw "Deployment failed with state $state"
        }

        $outputs = $deployment.properties.outputs
        Write-Status 'Infrastructure deployment completed successfully.' -Type Success
        Write-Host "Function App Name: $($outputs.functionAppName.value)"
        Write-Host "Function Hostname: $($outputs.functionAppHostname.value)"
        Write-Host "Managed Identity PrincipalId: $($outputs.functionAppPrincipalId.value)"
    }
}
catch {
    Write-Status $_.Exception.Message -Type Error
    throw
}
