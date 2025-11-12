#!/usr/bin/env pwsh

#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)] [string] $ResourceGroup,
    [Parameter(Mandatory = $true)] [string] $Location,
    [Parameter(Mandatory = $true)] [string] $Environment,
    [Parameter(Mandatory = $true)] [string] $JobName,
    [Parameter(Mandatory = $true)] [string] $ContainerRegistryName,
    [Parameter(Mandatory = $true)] [string] $ContainerImageName,
    [Parameter(Mandatory = $true)] [string] $RepoOwner,
    [Parameter(Mandatory = $true)] [string] $RepoName,
    [Parameter(Mandatory = $false)] [string] $IdentityId,
    [Parameter(Mandatory = $false)] [switch] $Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$image = "$ContainerRegistryName.azurecr.io/$ContainerImageName"

$cmd = @(
    'az containerapp job create',
    "--name `"$JobName`"",
    "--resource-group `"$ResourceGroup`"",
    "--environment `"$Environment`"",
    "--trigger-type Event",
    "--replica-timeout 1800",
    "--replica-retry-limit 0",
    "--replica-completion-count 1",
    "--parallelism 1",
    "--image `"$image`"",
    "--min-executions 0",
    "--max-executions 10",
    "--polling-interval 30",
    "--scale-rule-name `"github-runner`"",
    "--scale-rule-type `"github-runner`"",
    "--scale-rule-metadata `"githubAPIURL=https://api.github.com`" `"owner=$RepoOwner`" `"runnerScope=repo`" `"repos=$RepoName`" `"targetWorkflowQueueLength=1`"",
    "--scale-rule-auth `"personalAccessToken=personal-access-token`"",
    "--secrets `"personal-access-token=secretref:personal-access-token`"",
    "--env-vars `"GITHUB_PAT=secretref:personal-access-token`" `"REGISTRATION_TOKEN_API_URL=https://api.github.com/repos/$RepoOwner/$RepoName/actions/runners/registration-token`"",
    "--registry-server `"$ContainerRegistryName.azurecr.io`""
)

if ($IdentityId) {
    $cmd += "--mi-user-assigned `"$IdentityId`""
    $cmd += "--registry-identity `"$IdentityId`""
}

$full = $cmd -join ' '

Write-Output "Generated az CLI command to create the Container Apps job:"
Write-Output $full

if ($Execute) {
    Write-Output 'Executing command...'
    Invoke-Expression $full
}
