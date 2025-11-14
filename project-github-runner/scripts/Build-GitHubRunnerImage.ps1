#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $DockerfilePath = './Dockerfile.github',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $BuildContext = '.',

    [Parameter(Mandatory = $false)]
    [switch] $Push
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command -Name docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI is required to build the runner image.'
}

Write-Verbose "Building GitHub Actions runner image ${ImageTag} (version ${RunnerVersion}, arch ${RunnerArchitecture})"

$buildArgs = @(
    'build'
    '--file', (Resolve-Path -Path $DockerfilePath)
    $BuildContext
)

if ($PSCmdlet.ShouldProcess($ImageTag, 'docker build')) {
    $null = & docker @buildArgs
}

if ($Push.IsPresent) {
    Write-Verbose "Pushing image ${ImageTag}"
    if ($PSCmdlet.ShouldProcess($ImageTag, 'docker push')) {
        $null = & docker push $ImageTag
    }
}

Write-Verbose 'Runner image build complete.'