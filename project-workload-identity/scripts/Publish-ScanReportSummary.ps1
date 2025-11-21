#!/usr/bin/env pwsh
#Requires -Version 7.4
<#!
.SYNOPSIS
Publish the workload identity HTML report content into the GitHub Actions job summary.

.DESCRIPTION
Reads the generated workload-identity-report.html file, extracts the <body> contents, and appends the markup to
GITHUB_STEP_SUMMARY so that the workflow run shows the same findings inline. The summary also includes a download hint so
operators can retrieve the fully styled artifact.

.PARAMETER ReportPath
Full or relative path to the workload identity HTML report that Write-ScanReport.ps1 produced.

.PARAMETER SummaryPath
Optional override for the job-summary file path. Defaults to the GITHUB_STEP_SUMMARY environment variable provided by GitHub Actions.

.PARAMETER SummaryTitle
Optional title rendered above the embedded markup. Defaults to "Workload Identity Risk Report".

.PARAMETER ArtifactHint
Text that explains where to download the full styled report (for example the artifact name).

.EXAMPLE
./Publish-ScanReportSummary.ps1 -ReportPath ./out/workload-identity-report.html
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ReportPath,
    [Parameter()][ValidateNotNullOrEmpty()][string]$SummaryPath = $env:GITHUB_STEP_SUMMARY,
    [Parameter()][ValidateNotNullOrEmpty()][string]$SummaryTitle = 'Workload Identity Risk Report',
    [Parameter()][ValidateNotNullOrEmpty()][string]$ArtifactHint = 'Download the full styled artifact (wi-scan-artifacts/workload-identity-report.html) from the workflow run.'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -Path $ReportPath -PathType Leaf)) {
    throw "ReportPath '$ReportPath' was not found. Ensure Write-ScanReport.ps1 ran and produced the HTML file."
}

if (-not $SummaryPath) {
    throw 'GITHUB_STEP_SUMMARY is not available. This script must run within a GitHub Actions step or be supplied with -SummaryPath.'
}

$htmlContent = Get-Content -Path $ReportPath -Raw -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($htmlContent)) {
    throw "Report '$ReportPath' is empty."
}

$regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
$bodyMatch = [System.Text.RegularExpressions.Regex]::Match($htmlContent, '<body[^>]*>(?<body>[\s\S]+?)</body>', $regexOptions)
$bodyMarkup = if ($bodyMatch.Success) { $bodyMatch.Groups['body'].Value.Trim() } else { $htmlContent.Trim() }

$summaryLines = [System.Collections.Generic.List[string]]::new()
$summaryLines.Add("## $SummaryTitle")
$summaryLines.Add('')
$summaryLines.Add("$ArtifactHint")
$summaryLines.Add('')
$summaryLines.Add('<details open>')
$summaryLines.Add('<summary>Inline HTML snapshot (styles removed)</summary>')
$summaryLines.Add('')
$summaryLines.Add($bodyMarkup)
$summaryLines.Add('</details>')
$summaryLines.Add('')

$summaryLines | Add-Content -Path $SummaryPath -Encoding UTF8
