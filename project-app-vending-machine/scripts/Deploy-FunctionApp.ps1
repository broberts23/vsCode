#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
Packages and deploys the queue worker Function App to Azure.

.DESCRIPTION
Stages function_app.py, host.json, shared app_vending code, catalog, UTCM
templates, and pre-bundled Linux Python wheels. Uploads the zip to the app's
storage account with Azure AD (--auth-mode login) and sets
WEBSITE_RUN_FROM_PACKAGE to the private blob URL. The Function App system
identity reads the package (Storage Blob Data Owner already assigned in Bicep).

This path is required when AzureWebJobsStorage uses managed identity: Azure CLI
config-zip / functionapp deploy cannot zip-deploy Linux Consumption in that mode
(https://aka.ms/deployfromurl).
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$workerRoot = Join-Path $projectRoot 'worker'
$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("appvend-worker-{0}" -f ([guid]::NewGuid().Guid))
$zipPath = Join-Path ([System.IO.Path]::GetTempPath()) ("appvend-worker-{0}.zip" -f ([guid]::NewGuid().Guid))
$sitePackages = Join-Path $stagingRoot '.python_packages\lib\site-packages'
$packageContainer = 'appvend-packages'

$requirements = @'
azure-functions>=1.18.0
azure-data-tables>=12.5.0
azure-identity>=1.15.0
azure-storage-queue>=12.9.0
httpx>=0.26.0
msal>=1.26.0
pydantic>=2.5.0
'@

try {
    New-Item -ItemType Directory -Path $sitePackages -Force | Out-Null

    Copy-Item (Join-Path $workerRoot 'function_app.py') $stagingRoot
    Copy-Item (Join-Path $workerRoot 'host.json') $stagingRoot
    Copy-Item (Join-Path $projectRoot 'src\app_vending') (Join-Path $stagingRoot 'app_vending') -Recurse -Exclude '__pycache__', '*.pyc'
    Copy-Item (Join-Path $projectRoot 'catalog') (Join-Path $stagingRoot 'catalog') -Recurse

    $utcmStaging = Join-Path $stagingRoot 'samples\utcm'
    New-Item -ItemType Directory -Path $utcmStaging -Force | Out-Null
    Copy-Item (Join-Path $projectRoot 'samples\utcm\*.monitor.json') $utcmStaging
    New-Item -ItemType Directory -Path (Join-Path $utcmStaging 'generated') -Force | Out-Null

    # Pre-bundle wheels: remote Oryx build is not available with external package URL.
    $requirementsPath = Join-Path ([System.IO.Path]::GetTempPath()) ("appvend-worker-req-{0}.txt" -f ([guid]::NewGuid().Guid))
    Set-Content -Path $requirementsPath -Value $requirements -Encoding utf8
    Write-Host 'Bundling Linux Python 3.11 wheels into .python_packages...'
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

    # Keep a requirements.txt for visibility; packages are already in .python_packages.
    Set-Content -Path (Join-Path $stagingRoot 'requirements.txt') -Value $requirements -Encoding utf8

    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $stagingRoot '*') -DestinationPath $zipPath -Force
    Write-Host ("Package size: {0:N1} MB" -f ((Get-Item $zipPath).Length / 1MB))

    if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Deploy Function App via remote package URL')) {
        $settingsJson = az functionapp config appsettings list `
            --resource-group $ResourceGroupName `
            --name $FunctionAppName `
            -o json
        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to list Function App settings.'
        }
        $settingMap = @{}
        foreach ($s in ($settingsJson | ConvertFrom-Json)) {
            $settingMap[$s.name] = $s.value
        }

        $storageAccount = $settingMap['STORAGE_ACCOUNT_NAME']
        if (-not $storageAccount) {
            $storageAccount = $settingMap['AzureWebJobsStorage__accountName']
        }
        if (-not $storageAccount) {
            throw 'STORAGE_ACCOUNT_NAME / AzureWebJobsStorage__accountName not found on Function App.'
        }

        Write-Host "Ensuring blob container '$packageContainer' on storage account '$storageAccount'..."
        # Deployer needs data-plane RBAC when allowSharedKeyAccess is false.
        $storageId = az storage account show `
            --name $storageAccount `
            --resource-group $ResourceGroupName `
            --query id -o tsv
        if ($LASTEXITCODE -ne 0 -or -not $storageId) {
            throw "Failed to resolve storage account resource ID for '$storageAccount'."
        }
        $signerOid = az ad signed-in-user show --query id -o tsv 2>$null
        if ($signerOid) {
            Write-Host "Ensuring Storage Blob Data Contributor for signed-in user on storage account..."
            $null = az role assignment create `
                --assignee-object-id $signerOid `
                --assignee-principal-type User `
                --role 'Storage Blob Data Contributor' `
                --scope $storageId `
                -o none 2>&1
            # Role create may fail if assignment already exists; continue and let upload prove access.
            if ($LASTEXITCODE -eq 0) {
                Write-Host 'Waiting 30s for RBAC propagation...'
                Start-Sleep -Seconds 30
            }
        }

        $createOut = az storage container create `
            --account-name $storageAccount `
            --name $packageContainer `
            --auth-mode login `
            --public-access off `
            -o json 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw @"
Failed to create container '$packageContainer' (exit $LASTEXITCODE).
Your signed-in identity needs Storage Blob Data Contributor on storage account '$storageAccount'
(shared key access is disabled). Grant it, wait for RBAC to propagate, then retry.
Output: $createOut
"@
        }

        $blobName = 'worker-{0:yyyyMMddHHmmss}-{1}.zip' -f (Get-Date).ToUniversalTime(), ([guid]::NewGuid().ToString('N').Substring(0, 8))
        Write-Host "Uploading package to $storageAccount/$packageContainer/$blobName ..."
        $uploadOut = az storage blob upload `
            --account-name $storageAccount `
            --container-name $packageContainer `
            --name $blobName `
            --file $zipPath `
            --auth-mode login `
            --overwrite true `
            -o json 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw @"
Failed to upload package blob (exit $LASTEXITCODE).
Your signed-in identity needs Storage Blob Data Contributor on '$storageAccount'.
Output: $uploadOut
"@
        }

        $packageUrl = "https://$storageAccount.blob.core.windows.net/$packageContainer/$blobName"
        Write-Host "Setting WEBSITE_RUN_FROM_PACKAGE=$packageUrl"
        az functionapp config appsettings set `
            --resource-group $ResourceGroupName `
            --name $FunctionAppName `
            --settings `
                "WEBSITE_RUN_FROM_PACKAGE=$packageUrl" `
                'WEBSITE_RUN_FROM_PACKAGE_BLOB_MI_RESOURCE_ID=SystemAssigned' `
                'SCM_DO_BUILD_DURING_DEPLOYMENT=false' `
            --output none
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set WEBSITE_RUN_FROM_PACKAGE (exit $LASTEXITCODE)."
        }

        Write-Host 'Restarting Function App...'
        az functionapp restart `
            --resource-group $ResourceGroupName `
            --name $FunctionAppName `
            --output none

        Write-Host "Published worker package to Function App '$FunctionAppName' via $packageUrl"
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
