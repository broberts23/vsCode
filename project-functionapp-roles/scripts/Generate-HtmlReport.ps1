#!/usr/bin/env pwsh
#Requires -Version 7.4
<#
.SYNOPSIS
    Generate HTML test report from NUnit XML results

.DESCRIPTION
    Converts the NUnit XML test results into a styled HTML report for easy viewing

.EXAMPLE
    ./Generate-HtmlReport.ps1
#>

[CmdletBinding()]
param()

$xmlPath = './tests/TestResults.xml'
$htmlPath = './tests/TestResults.html'

if (-not (Test-Path $xmlPath)) {
    Write-Error "Test results not found at $xmlPath. Run Generate-TestReports.ps1 first."
    exit 1
}

Write-Host "Loading test results from $xmlPath..." -ForegroundColor Cyan

[xml]$xml = Get-Content $xmlPath

$results = $xml.'test-results'
$passed = [int]$results.total - [int]$results.failures - [int]$results.errors
$failed = [int]$results.failures + [int]$results.errors
$passRate = if ([int]$results.total -gt 0) { 
    [math]::Round(($passed / [int]$results.total) * 100, 1) 
}
else { 
    0 
}

$statusColor = if ($failed -eq 0) { '#28a745' } else { '#dc3545' }
$statusText = if ($failed -eq 0) { '✅ All Tests Passing' } else { "⚠️ $failed Test(s) Failed" }

# Load code coverage if available
$coverage = 0
$coveragePath = './tests/Coverage.xml'
if (Test-Path $coveragePath) {
    [xml]$coverageXml = Get-Content $coveragePath
    # Get the class-level LINE counter (not method-level)
    $lineCounter = $coverageXml.SelectSingleNode("//class/counter[@type='LINE']")
    if ($lineCounter) {
        $coveredLines = [int]$lineCounter.covered
        $missedLines = [int]$lineCounter.missed
        $totalLines = $coveredLines + $missedLines
        if ($totalLines -gt 0) {
            $coverage = [math]::Round(($coveredLines / $totalLines) * 100, 1)
        }
    }
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Results - Password Reset Function App</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2rem; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 0.95rem; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label {
            color: #6c757d;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        .total { color: #007bff; }
        .rate { color: #17a2b8; }
        .status-banner {
            background: $statusColor;
            color: white;
            padding: 15px 30px;
            text-align: center;
            font-size: 1.2rem;
            font-weight: 500;
        }
        .tests {
            padding: 30px;
        }
        .test-suite {
            margin-bottom: 30px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }
        .suite-header {
            background: #e9ecef;
            padding: 15px 20px;
            font-weight: 600;
            color: #495057;
            cursor: pointer;
            user-select: none;
        }
        .suite-header:hover { background: #dee2e6; }
        .test-cases {
            padding: 15px;
        }
        .test-case {
            display: flex;
            align-items: center;
            padding: 12px;
            border-bottom: 1px solid #f1f3f5;
        }
        .test-case:last-child { border-bottom: none; }
        .test-case .icon {
            font-size: 1.2rem;
            margin-right: 12px;
        }
        .test-case .name {
            flex: 1;
            font-size: 0.95rem;
        }
        .test-case .time {
            color: #6c757d;
            font-size: 0.85rem;
            margin-left: 12px;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px 30px;
            text-align: center;
            color: #6c757d;
            font-size: 0.85rem;
            border-top: 1px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Password Reset Function App</h1>
            <p>Test Results Report - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <div class="status-banner">
            $statusText
        </div>
        
        <div class="summary">
            <div class="stat-card">
                <div class="value passed">$passed</div>
                <div class="label">Passed</div>
            </div>
            <div class="stat-card">
                <div class="value failed">$failed</div>
                <div class="label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="value total">$($results.total)</div>
                <div class="label">Total</div>
            </div>
            <div class="stat-card">
                <div class="value rate">$passRate%</div>
                <div class="label">Pass Rate</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #6f42c1;">$coverage%</div>
                <div class="label">Coverage</div>
            </div>
        </div>
        
        <div class="tests">
            <h2 style="margin-bottom: 20px; color: #343a40;">Test Suites</h2>
"@

# Process test suites
foreach ($suite in $xml.SelectNodes("//test-suite[@type='TestFixture' and @name!='Pester']")) {
    $suiteName = $suite.name -replace '.*/', '' -replace '.Tests.ps1', ''
    $html += @"
            <div class="test-suite">
                <div class="suite-header">📦 $suiteName</div>
                <div class="test-cases">
"@
    
    foreach ($testCase in $suite.SelectNodes(".//test-case")) {
        $name = $testCase.description
        $time = [math]::Round([double]$testCase.time, 3)
        $icon = if ($testCase.success -eq 'True') { '✅' } else { '❌' }
        
        $html += @"
                    <div class="test-case">
                        <div class="icon">$icon</div>
                        <div class="name">$name</div>
                        <div class="time">${time}s</div>
                    </div>
"@
    }
    
    $html += @"
                </div>
            </div>
"@
}

$html += @"
        </div>
        
        <div class="footer">
            <p>PowerShell 7.4 • Pester 5.7.1 • Azure Functions v4</p>
            <p style="margin-top: 8px;">Generated by Generate-HtmlReport.ps1</p>
        </div>
    </div>
</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "✅ HTML report generated:" -ForegroundColor Green
Write-Host "   📊 $htmlPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Open in browser:" -ForegroundColor Yellow
Write-Host "   xdg-open $htmlPath" -ForegroundColor White
