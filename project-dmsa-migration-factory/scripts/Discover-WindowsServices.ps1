[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ComputerName
)

$ServiceObjects = Get-CimInstance -ClassName Win32_Service

if ($null -eq $ServiceObjects -or $ServiceObjects.Count -eq 0) {
    $ServiceObjects = Get-WmiObject -Class Win32_Service
}

$FilteredServices = $ServiceObjects | Where-Object { 
    $_.StartMode -ne "Disabled" -and 
    $_.StartName -notmatch "LocalSystem|LocalService|NetworkService" 
} | ForEach-Object {
    [PSCustomObject]@{
        Name        = $_.Name
        DisplayName = $_.DisplayName
        StartName   = $_.StartName
        State       = $_.State
    }   
}

if ($FilteredServices) {
    Write-Output ($FilteredServices | ConvertTo-Json -Depth 4 -Compress)
}
else {
    Write-Output "[]"
}