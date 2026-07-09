param(
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,

    [Parameter(Mandatory = $false)]
    [string]$AccountName,

    [Parameter(Mandatory = $false)]
    [switch]$ClearDMSA
)

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$regName = "DelegatedMSAEnabled"

if ($ClearDMSA) {
    Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    "Registry key $regPath\$regName removed"
}
else {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name $regName -Value 1 -Type DWORD -Force
    "Registry key $regPath\$regName set to 1"
}

if (-not $AccountName) {
    return
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    throw "Service $ServiceName was not found"
}

$CimService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"

$Result = Invoke-CimMethod -InputObject $CimService -MethodName Change -Arguments @{
    StartName     = $AccountName
    StartPassword = ""
}

sc.exe managedaccount $CimService true

if ($Result.ReturnValue -ne 0) {
    throw "Failed to configure $ServiceName to run as $AccountName. WMI Error Code: $($Result.ReturnValue)"
}

"Service $ServiceName configured to run as $AccountName"