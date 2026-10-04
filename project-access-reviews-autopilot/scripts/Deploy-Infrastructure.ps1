<#
.SYNOPSIS
  Deploy Access Reviews Autopilot infrastructure (MI-only, no resource keys in app settings).

.NOTES
  1. Deploy infra first with an empty containerImage.
  2. Build/push the image to the output ACR with az acr build (uses MI AcrPush separately or az login).
  3. Redeploy with -ContainerImage <loginServer>/ara:dev
  4. Store Slack secrets in Key Vault: slack-signing-secret, slack-bot-token.
  5. Pass -SlackChannelId so worker-notify can post cards (not a secret; ACA env var).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [string]$Location = 'australiaeast',

    [Parameter(Mandatory)]
    [string]$TenantId,

    [string]$ApiClientId = '',

    [string]$ApiAudience = '',

    [string]$SlackChannelId = '',

    [string]$LabIdentityMapSlackUserId = '',

    [string]$ContainerImage = '',

    [string]$BaseName = 'ara',

    [string]$Environment = 'dev'
)

if (-not $ApiAudience -and $ApiClientId) {
    $ApiAudience = "api://$ApiClientId"
}

$ErrorActionPreference = 'Stop'

if (-not (Get-AzContext)) {
    throw 'Run Connect-AzAccount first.'
}

if (-not (Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue)) {
    New-AzResourceGroup -Name $ResourceGroup -Location $Location | Out-Null
}

$params = @{
    deploymentEnvironment     = $Environment
    baseName                  = $BaseName
    tenantId                  = $TenantId
    apiClientId               = $ApiClientId
    apiAudience               = $ApiAudience
    slackChannelId            = $SlackChannelId
    labIdentityMapSlackUserId = $LabIdentityMapSlackUserId
    containerImage            = $ContainerImage
}

$deployment = New-AzResourceGroupDeployment `
    -Name "ara-$(Get-Date -Format 'yyyyMMddHHmmss')" `
    -ResourceGroupName $ResourceGroup `
    -TemplateFile (Join-Path $PSScriptRoot '..\infra\main.bicep') `
    -TemplateParameterObject $params `
    -Verbose

$deployment.Outputs | Format-Table -AutoSize

# New subscriptions auto-create a $Default TrueFilter. Keep only the named SQL
# filters from Bicep; otherwise apply/notify both receive every message.
$sbNamespace = $deployment.Outputs.serviceBusNamespace.Value -replace '\.servicebus\.windows\.net$', ''
if ($sbNamespace) {
    foreach ($pair in @(
            @{ Sub = 'slack-notify'; Keep = 'notify-filter' },
            @{ Sub = 'apply-decision'; Keep = 'apply-filter' }
        )) {
        $rules = @(az servicebus topic subscription rule list `
                --resource-group $ResourceGroup `
                --namespace-name $sbNamespace `
                --topic-name review-work `
                --subscription-name $pair.Sub `
                --query '[].name' -o tsv 2>$null)
        foreach ($ruleName in $rules) {
            if ($ruleName -and $ruleName -ne $pair.Keep) {
                Write-Host "Removing stray Service Bus rule '$ruleName' on $($pair.Sub)"
                az servicebus topic subscription rule delete `
                    --resource-group $ResourceGroup `
                    --namespace-name $sbNamespace `
                    --topic-name review-work `
                    --subscription-name $pair.Sub `
                    --name $ruleName `
                    --yes 2>$null | Out-Null
            }
        }
    }
}

Write-Host @'
Next steps:
  1. az acr build -r <acrLoginServer> -t ara:dev .
  2. Re-run this script with -ContainerImage <acrLoginServer>/ara:dev -ApiClientId ... -SlackChannelId ...
  3. az keyvault secret set --vault-name <kv> --name slack-signing-secret --value <secret>
  4. az keyvault secret set --vault-name <kv> --name slack-bot-token --value <xoxb-...>
  5. Point Slack Request URL to https://<apiFqdn>/slack/interactions
  6. Smoke-test: no AccountKey/SharedAccessKey/Cosmos keys in ACA env
'@
