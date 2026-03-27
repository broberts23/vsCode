#!/usr/bin/env pwsh
#Requires -Version 7.4

using namespace System.Net

param($Request, $TriggerMetadata)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '..\shared\AgentVendingMachine.psm1') -Force

try {
    $requiredRole = Get-EnvironmentSetting -Name 'REQUIRED_ADMIN_ROLE' -DefaultValue 'Agent.Vending.Admin'
    $principal = Get-ClientPrincipal -Request $Request

    if (-not (Test-PrincipalHasRole -Principal $principal -RequiredRole $requiredRole)) {
        Push-OutputBinding -Name Response -Value (New-JsonResponse -StatusCode ([HttpStatusCode]::Forbidden) -Body @{
                error   = 'Forbidden'
                message = "The caller must present the '$requiredRole' app role via App Service Authentication."
            })
        return
    }

    $requestBody = ConvertFrom-FunctionRequestBody -Request $Request
    $catalog = Get-OfferCatalog
    $offer = Get-OfferDefinition -OfferingId $requestBody.offeringId -Catalog $catalog
    $sponsorObjectIds = @($requestBody.sponsorObjectIds)
    if ($sponsorObjectIds.Count -eq 0) {
        $sponsorObjectIds = Get-DefaultObjectIds -EnvironmentVariableName 'DEFAULT_AGENT_SPONSOR_OBJECT_IDS'
    }

    $ownerObjectIds = @($requestBody.ownerObjectIds)
    if ($ownerObjectIds.Count -eq 0) {
        $ownerObjectIds = Get-DefaultObjectIds -EnvironmentVariableName 'DEFAULT_AGENT_OWNER_OBJECT_IDS'
    }

    $executionMode = Get-EnvironmentSetting -Name 'AGENT_VENDING_EXECUTION_MODE' -DefaultValue 'DryRun'
    $blueprintPlan = New-BlueprintPlan -Offer $offer -SponsorObjectIds $sponsorObjectIds -OwnerObjectIds $ownerObjectIds

    $response = @{
        system         = 'Agent Vending Machine'
        operation      = 'BootstrapOffering'
        executionMode  = $executionMode
        offeringId     = $offer.offeringId
        prerequisites  = @(
            'Tenant is enabled for Microsoft Agent 365 through the Frontier program.',
            'Function App managed identity exists and is allowed to call Microsoft Graph.',
            'The automation identity has the necessary Agent ID and Graph permissions for bootstrap.',
            'Entitlement Management catalog owners or Identity Governance administrators are available to create the access package and policy.'
        )
        blueprint      = $blueprintPlan
        accessPackage  = $offer.accessPackage
        nextSteps      = @(
            'Execute the graphRequests in order, or wire them into a deployment script.',
            'Create the access package and assignment policy using the offer accessPackage block.',
            'Persist the resulting blueprint appId, blueprint principal objectId, access package id, and assignment policy id back into the offer catalog before enabling live dispense.'
        )
    }

    Push-OutputBinding -Name Response -Value (New-JsonResponse -StatusCode ([HttpStatusCode]::OK) -Body $response)
}
catch {
    Push-OutputBinding -Name Response -Value (New-JsonResponse -StatusCode ([HttpStatusCode]::InternalServerError) -Body @{
            error   = 'BootstrapFailed'
            message = $_.Exception.Message
        })
}