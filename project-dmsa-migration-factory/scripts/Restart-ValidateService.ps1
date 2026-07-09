param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,

    [Parameter(Mandatory = $false)]
    [string]$ExpectedAccount
)
Start-Sleep -Seconds 5
Restart-Service -Name $ServiceName -Force -ErrorAction Stop
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    throw "Service $ServiceName was not found after restart"
}

$cim = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -eq $ServiceName }
$startName = if ($cim) { $cim.StartName } else { "unknown" }
$running = $svc.Status -eq 'Running'
$accountMatches = [string]::IsNullOrWhiteSpace($ExpectedAccount) -or $startName -ieq $ExpectedAccount

[pscustomobject]@{
    Name      = $ServiceName
    Running   = ($running -and $accountMatches)
    StartName = $startName
    Message   = if ($running -and $accountMatches) { "service validated" } else { "service validation failed" }
} | ConvertTo-Json -Depth 4
