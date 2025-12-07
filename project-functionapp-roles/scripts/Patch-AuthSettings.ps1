#!/usr/bin/env pwsh
#Requires -Version 7.4

param(
    [string]$ResourceGroupName = 'rg-pwdreset-three-dev',
    [string]$FunctionAppName = 'pwdreset-func-dev-5egrzquh3py72',
    [string]$TenantId = '7c029110-ec6b-48a2-a1ec-5bdec806f9ce',
    [string]$ApiAppId = '7a7a8553-e5bd-4072-abb3-cce9378f86db',
    [string]$ClientId = '31a1bcf9-8def-4971-bcd8-13da25feefaa'
)

$ErrorActionPreference = 'Stop'

Write-Host "Getting Function App resource..." -ForegroundColor Cyan
$resourceId = "/subscriptions/$( (Get-AzContext).Subscription.Id )/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$FunctionAppName/config/authsettingsV2"

Write-Host "Resource ID: $resourceId" -ForegroundColor Gray

# Get current settings
try {
    $currentSettings = Get-AzResource -ResourceId $resourceId -ErrorAction Stop
}
catch {
    Write-Error "Failed to get auth settings: $_"
    exit 1
}

Write-Host "Current OpenIdIssuer: $($currentSettings.Properties.identityProviders.azureActiveDirectory.registration.openIdIssuer)" -ForegroundColor Yellow
Write-Host "Current ClientId: $($currentSettings.Properties.identityProviders.azureActiveDirectory.registration.clientId)" -ForegroundColor Yellow
Write-Host "Current TokenStore Enabled: $($currentSettings.Properties.login.tokenStore.enabled)" -ForegroundColor Yellow

# Update settings
$properties = $currentSettings.Properties

# 1. Fix OpenIdIssuer (Hardcode to v2.0 endpoint)
$newIssuer = "https://login.microsoftonline.com/$TenantId/v2.0"
$registration = @{
    openIdIssuer = $newIssuer
    clientId     = $ApiAppId
}
$properties.identityProviders.azureActiveDirectory.registration = $registration

# 2. Fix AllowedAudiences (Add ApiAppId + App ID URI)
$audiences = @()
if ($properties.identityProviders.azureActiveDirectory.validation.allowedAudiences) {
    $audiences = @($properties.identityProviders.azureActiveDirectory.validation.allowedAudiences)
}

$requiredAudiences = @(
    $ApiAppId,
    "api://$ApiAppId"
)

foreach ($audience in $requiredAudiences) {
    if ($audience -and ($audiences -notcontains $audience)) {
        $audiences += $audience
    }
}

# 3. Enable Auth
$properties.globalValidation.requireAuthentication = $true

# 4. Remove Default Authorization Policy
$validation = $properties.identityProviders.azureActiveDirectory.validation
if (-not $validation) {
    $validation = @{}
}

$validation.allowedAudiences = $audiences

if ($validation.PSObject.Properties.Name -contains 'defaultAuthorizationPolicy') {
    $validation.PSObject.Properties.Remove('defaultAuthorizationPolicy')
}

$properties.identityProviders.azureActiveDirectory.validation = $validation

Write-Host "Updating Auth Settings..." -ForegroundColor Cyan
Write-Host "New Issuer: $newIssuer" -ForegroundColor Gray
Write-Host "ClientId: $($registration.clientId)" -ForegroundColor Gray
Write-Host "Audiences: $($audiences -join ', ')" -ForegroundColor Gray

# Update the resource
$currentSettings.Properties = $properties
Set-AzResource -ResourceId $resourceId -Properties $properties -Force -ErrorAction Stop | Out-Null

# Read back to verify
$updatedSettings = Get-AzResource -ResourceId $resourceId
Write-Host "Update Complete." -ForegroundColor Green
Write-Host "Verified Issuer: $($updatedSettings.Properties.identityProviders.azureActiveDirectory.registration.openIdIssuer)" -ForegroundColor Green

Write-Host "Full Properties:" -ForegroundColor Cyan
$updatedSettings.Properties | ConvertTo-Json -Depth 10 | Write-Host
