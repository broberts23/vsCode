<#
.SYNOPSIS
  Build and push the lab image to ACR (admin user disabled — uses az acr build).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AcrName,

    [string]$ImageTag = 'ara:dev'
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')

Push-Location $root
try {
    az acr build --registry $AcrName --image $ImageTag .
    if ($LASTEXITCODE -ne 0) { throw 'az acr build failed' }
    Write-Host "Pushed $ImageTag to $AcrName"
}
finally {
    Pop-Location
}
