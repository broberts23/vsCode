#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Packages and deploys the FastAPI Web App to Azure App Service.

.DESCRIPTION
Stages api/, shared app_vending code, catalog, and a Linux manylinux wheel
bundle under .python_packages so App Service does not need a remote Oryx
build (which hangs/502s on small B1 plans). Deploys with Azure CLI zip deploy
using the caller's Azure AD identity (SCM basic auth is disabled in Bicep).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$ApiAppName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("appvend-api-{0}" -f ([guid]::NewGuid().Guid))
$zipPath = Join-Path ([System.IO.Path]::GetTempPath()) ("appvend-api-{0}.zip" -f ([guid]::NewGuid().Guid))
$sitePackages = Join-Path $stagingRoot '.python_packages\lib\site-packages'

$requirements = @'
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
gunicorn>=21.2.0
azure-data-tables>=12.5.0
azure-identity>=1.15.0
azure-storage-queue>=12.9.0
httpx>=0.26.0
msal>=1.26.0
pydantic>=2.5.0
'@

try {
    New-Item -ItemType Directory -Path $sitePackages -Force | Out-Null

    Copy-Item (Join-Path $projectRoot 'api') (Join-Path $stagingRoot 'api') -Recurse -Exclude '__pycache__', '*.pyc'
    Remove-Item (Join-Path $stagingRoot 'api\requirements.txt') -ErrorAction SilentlyContinue
    Copy-Item (Join-Path $projectRoot 'src\app_vending') (Join-Path $stagingRoot 'app_vending') -Recurse -Exclude '__pycache__', '*.pyc'
    Copy-Item (Join-Path $projectRoot 'catalog') (Join-Path $stagingRoot 'catalog') -Recurse

    # requirements used only for local wheel bundling — omit from zip so Kudu/Oryx
    # has nothing to build (remote builds hang/502 on small B1 plans).
    $requirementsPath = Join-Path ([System.IO.Path]::GetTempPath()) ("appvend-req-{0}.txt" -f ([guid]::NewGuid().Guid))
    Set-Content -Path $requirementsPath -Value $requirements -Encoding utf8

    Write-Host 'Bundling Linux Python 3.11 wheels into .python_packages (no remote Oryx)...'
    python -m pip install `
        --disable-pip-version-check `
        --no-compile `
        --target $sitePackages `
        --platform manylinux2014_x86_64 `
        --implementation cp `
        --python-version 311 `
        --only-binary=:all: `
        -r $requirementsPath
    if ($LASTEXITCODE -ne 0) {
        throw "pip install of Linux wheels failed with exit code $LASTEXITCODE"
    }
    Remove-Item $requirementsPath -Force -ErrorAction SilentlyContinue

    @'
[config]
SCM_DO_BUILD_DURING_DEPLOYMENT = false
'@ | Set-Content -Path (Join-Path $stagingRoot '.deployment') -Encoding utf8

    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $stagingRoot '*') -DestinationPath $zipPath -Force
    Write-Host ("Package size: {0:N1} MB" -f ((Get-Item $zipPath).Length / 1MB))

    if ($PSCmdlet.ShouldProcess($ApiAppName, 'Zip-deploy API Web App')) {
        az webapp config appsettings set `
            --resource-group $ResourceGroupName `
            --name $ApiAppName `
            --settings `
                SCM_DO_BUILD_DURING_DEPLOYMENT=false `
                ENABLE_ORYX_BUILD=false `
                WEBSITES_PORT=8000 `
                PYTHONPATH='/home/site/wwwroot:/home/site/wwwroot/.python_packages/lib/site-packages' `
            --output none

        az webapp config set `
            --resource-group $ResourceGroupName `
            --name $ApiAppName `
            --startup-file "python -m gunicorn -w 2 -k uvicorn.workers.UvicornWorker api.main:app --bind=0.0.0.0:8000" `
            --output none

        Write-Host 'Clearing stuck SCM build processes via Kudu (Azure AD)...'
        $scmBase = "https://$ApiAppName.scm.azurewebsites.net"
        $armToken = (az account get-access-token --resource 'https://management.azure.com/' --query accessToken -o tsv)
        if (-not $armToken) {
            throw 'Failed to acquire Azure AD access token for Kudu.'
        }
        $aadHeaders = @{
            Authorization                  = "Bearer $armToken"
            'Content-Type'                 = 'application/json'
            SCM_DO_BUILD_DURING_DEPLOYMENT = 'false'
        }
        $killBody = '{"command":"pkill -9 -f oryx || true; pkill -9 -f build.sh || true; echo cleared","dir":"/home"}'
        try {
            Invoke-RestMethod -Uri "$scmBase/api/command" -Method POST -Headers $aadHeaders -Body $killBody -TimeoutSec 60 | Out-Null
        }
        catch {
            Write-Warning "Could not clear SCM processes: $($_.Exception.Message)"
        }

        Write-Host 'Publishing zip via Azure CLI (Azure AD; SCM basic auth disabled)...'
        az webapp deploy `
            --resource-group $ResourceGroupName `
            --name $ApiAppName `
            --src-path $zipPath `
            --type zip `
            --async false `
            --clean true `
            --restart true
        if ($LASTEXITCODE -ne 0) {
            throw "az webapp deploy failed with exit code $LASTEXITCODE"
        }

        Write-Host "Published API package to Web App '$ApiAppName'."
        Write-Host "Health: https://$ApiAppName.azurewebsites.net/health"
        Write-Host "Swagger (after auth): https://$ApiAppName.azurewebsites.net/docs"
    }
}
finally {
    if (Test-Path $stagingRoot) {
        Remove-Item $stagingRoot -Recurse -Force
    }
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
}
