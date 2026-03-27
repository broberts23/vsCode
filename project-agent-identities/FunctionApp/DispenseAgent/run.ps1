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
    if ([string]::IsNullOrWhiteSpace($requestBody.offeringId) -or [string]::IsNullOrWhiteSpace($requestBody.instanceDisplayName)) {
        Push-OutputBinding -Name Response -Value (New-JsonResponse -StatusCode ([HttpStatusCode]::BadRequest) -Body @{
                error   = 'BadRequest'
                message = 'offeringId and instanceDisplayName are required.'
            })
        return
    }

    $catalog = Get-OfferCatalog
    $offer = Get-OfferDefinition -OfferingId $requestBody.offeringId -Catalog $catalog
    $sponsorObjectIds = @($requestBody.sponsorObjectIds)
    if ($sponsorObjectIds.Count -eq 0) {
        $sponsorObjectIds = Get-DefaultObjectIds -EnvironmentVariableName 'DEFAULT_AGENT_SPONSOR_OBJECT_IDS'
    }

    $blueprintAppId = if (-not [string]::IsNullOrWhiteSpace($requestBody.blueprintAppId)) { $requestBody.blueprintAppId } else { '{bootstrap-output-blueprint-app-id}' }
    $executionMode = Get-EnvironmentSetting -Name 'AGENT_VENDING_EXECUTION_MODE' -DefaultValue 'DryRun'
    $agentPlan = New-AgentIdentityPlan -Offer $offer -InstanceDisplayName $requestBody.instanceDisplayName -BlueprintAppId $blueprintAppId -SponsorObjectIds $sponsorObjectIds

    $result = [ordered]@{
        system        = 'Agent Vending Machine'
        operation     = 'DispenseAgent'
        executionMode = $executionMode
        offeringId    = $offer.offeringId
        request       = @{
            offeringId          = $requestBody.offeringId
            instanceDisplayName = $requestBody.instanceDisplayName
            createAgentUser     = [bool]$requestBody.createAgentUser
            justification       = $requestBody.justification
        }
        graphRequest  = $agentPlan.graphRequest
        governance    = @{
            accessPackage = $agentPlan.accessPackage
            note          = 'Access package assignment can be sponsor-approved, agent-requested, or directly assigned after the identity exists.'
        }
        agentUser     = if ($requestBody.createAgentUser -or $offer.agentUser.enabledByDefault) { $agentPlan.agentUser } else { $null }
        outputs       = @{
            expectedArtifacts = @(
                'Agent identity objectId',
                'Agent identity appId',
                'Access package assignment request id',
                'Optional agent user objectId'
            )
        }
    }

    if ($executionMode -eq 'Live') {
        $createdAgent = Invoke-GraphRequest -Method 'POST' -Uri $agentPlan.graphRequest.uri -Body $agentPlan.graphRequest.body
        $result.liveResult = @{
            agentIdentityObjectId = $createdAgent.id
            agentIdentityAppId    = $createdAgent.appId
            note                  = 'Live mode currently creates the agent identity. Access package assignment and agent user creation remain explicit follow-on actions in this scaffold.'
        }
    }

    Push-OutputBinding -Name Response -Value (New-JsonResponse -StatusCode ([HttpStatusCode]::OK) -Body $result)
}
catch {
    Push-OutputBinding -Name Response -Value (New-JsonResponse -StatusCode ([HttpStatusCode]::InternalServerError) -Body @{
            error   = 'DispenseAgentFailed'
            message = $_.Exception.Message
        })
}