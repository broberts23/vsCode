#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Generate Pester test reports with coverage

.DESCRIPTION
    Runs Pester tests and generates NUnitXml, JaCoCo coverage, and HTML reports

.EXAMPLE
    ./Generate-TestReports.ps1
#>

[CmdletBinding()]
param()

$config = New-PesterConfiguration
# Only run unit tests (integration tests have Pester 5 scoping issues with Invoke-Expression pattern)
$config.Run.Path = './tests/Unit'
$config.Run.PassThru = $true
$config.TestResult.Enabled = $true
$config.TestResult.OutputPath = './tests/TestResults.xml'
$config.TestResult.OutputFormat = 'NUnitXml'
$config.CodeCoverage.Enabled = $true
# Only measure coverage of unit-testable code (exclude run.ps1 entry point which requires integration tests)
$config.CodeCoverage.Path = './Modules/**/*.psm1'
$config.CodeCoverage.OutputPath = './tests/Coverage.xml'
$config.CodeCoverage.OutputFormat = 'JaCoCo'

Write-Host "Running Pester unit tests with coverage..." -ForegroundColor Cyan
Write-Host "(Integration tests skipped - they use Invoke-Expression pattern that has scoping issues in Pester 5)" -ForegroundColor Yellow
$result = Invoke-Pester -Configuration $config

Write-Host ""
Write-Host "✅ Reports generated:" -ForegroundColor Green
Write-Host "   📄 ./tests/TestResults.xml" -ForegroundColor Cyan
Write-Host "   📊 ./tests/Coverage.xml" -ForegroundColor Cyan

# Generate HTML report
Write-Host ""
Write-Host "Generating HTML report..." -ForegroundColor Cyan
& "$PSScriptRoot/Generate-HtmlReport.ps1"

Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "   Total: $($result.TotalCount)" -ForegroundColor White
Write-Host "   Passed: $($result.PassedCount)" -ForegroundColor Green
Write-Host "   Failed: $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -eq 0) { 'Green' } else { 'Red' })
Write-Host "   Coverage: $([math]::Round($result.CodeCoverage.CoveragePercent, 1))%" -ForegroundColor Cyan
