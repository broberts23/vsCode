#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Downloads and extracts System.IdentityModel.Tokens.Jwt NuGet package
.DESCRIPTION
    Downloads the System.IdentityModel.Tokens.Jwt NuGet package and its dependencies,
    extracts the .NET 6.0+ compatible DLLs, and places them in the bin folder for Azure Functions deployment.
.LINK
    https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/
#>

[CmdletBinding()]
param(
    [string]$Version = "7.0.0",
    [string]$TargetFramework = "net6.0",
    [string]$OutputPath = "../bin"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "📦 Installing JWT dependencies..." -ForegroundColor Cyan

# Resolve output path
$binPath = Join-Path $PSScriptRoot $OutputPath
if (-not (Test-Path $binPath)) {
    New-Item -Path $binPath -ItemType Directory -Force | Out-Null
    Write-Host "✓ Created bin directory: $binPath" -ForegroundColor Green
}

# Create temp directory
$tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "jwt-nuget-$(Get-Random)"
New-Item -Path $tempPath -ItemType Directory -Force | Out-Null

try {
    # Download packages
    $packages = @(
        @{ Name = "System.IdentityModel.Tokens.Jwt"; Version = $Version }
        @{ Name = "Microsoft.IdentityModel.Tokens"; Version = "7.0.0" }
        @{ Name = "Microsoft.IdentityModel.Logging"; Version = "7.0.0" }
        @{ Name = "Microsoft.IdentityModel.JsonWebTokens"; Version = "7.0.0" }
    )

    foreach ($package in $packages) {
        $pkgName = $package.Name
        $pkgVersion = $package.Version
        $nugetUrl = "https://www.nuget.org/api/v2/package/$pkgName/$pkgVersion"
        $nupkgPath = Join-Path $tempPath "$pkgName.$pkgVersion.nupkg"
        
        Write-Host "  Downloading $pkgName $pkgVersion..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $nugetUrl -OutFile $nupkgPath -UseBasicParsing
        
        # Extract (nupkg is just a zip file)
        $extractPath = Join-Path $tempPath $pkgName
        Expand-Archive -Path $nupkgPath -DestinationPath $extractPath -Force
        
        # Find the DLL for the target framework
        $dllPath = Get-ChildItem -Path $extractPath -Filter "$pkgName.dll" -Recurse | 
            Where-Object { $_.FullName -match "lib[/\\]$TargetFramework" } |
            Select-Object -First 1
        
        if ($dllPath) {
            Copy-Item -Path $dllPath.FullName -Destination $binPath -Force
            Write-Host "  ✓ Extracted $($dllPath.Name)" -ForegroundColor Green
        } else {
            Write-Warning "Could not find DLL for $pkgName in $TargetFramework"
        }
    }
    
    Write-Host ""
    Write-Host "✅ JWT dependencies installed successfully!" -ForegroundColor Green
    Write-Host "📁 Location: $binPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "DLLs extracted:" -ForegroundColor Yellow
    Get-ChildItem -Path $binPath -Filter "*.dll" | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor White
    }
    
} finally {
    # Cleanup
    if (Test-Path $tempPath) {
        Remove-Item -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
