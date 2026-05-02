#!/usr/bin/env powershell
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainNetBiosName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SafeModeAdminPasswordBase64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Initialize logging
$logDir = 'C:\temp'
$logFile = Join-Path $logDir "Bootstrap-ADDSDomain-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Information' { Write-Information -MessageData $logMessage -InformationAction Continue }
        'Warning' { Write-Warning -Message $Message }
        'Error' { Write-Error -Message $Message }
    }

    try {
        Add-Content -Path $script:logFile -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
    }
}

try {
    Write-Log "Starting AD DS bootstrap (promotion only) for domain: $DomainName"

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run as Administrator'
    }

    Write-Log 'Checking for unformatted disks...'
    $rawDisk = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' } | Select-Object -First 1
    if ($rawDisk) {
        Write-Log "Formatting disk $($rawDisk.Number) for AD DS data..."
        Initialize-Disk -Number $rawDisk.Number -PartitionStyle GPT -PassThru |
        New-Partition -DriveLetter F -UseMaximumSize |
        Format-Volume -FileSystem NTFS -NewFileSystemLabel 'ADDS_Data' -Confirm:$false
        Write-Log 'Disk formatted successfully as F:'
    }
    else {
        Write-Log 'No raw disk found; using C: for AD DS data (not recommended for production)' -Level Warning
    }

    $databasePath = if (Test-Path 'F:\') { 'F:\NTDS' } else { 'C:\NTDS' }
    $logPath = if (Test-Path 'F:\') { 'F:\NTDS\Logs' } else { 'C:\NTDS\Logs' }
    $sysvolPath = if (Test-Path 'F:\') { 'F:\SYSVOL' } else { 'C:\SYSVOL' }

    Write-Log 'Installing AD-Domain-Services Windows Feature...'
    $featureResult = Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    if (-not $featureResult.Success) {
        throw 'Failed to install AD-Domain-Services feature'
    }

    $isDC = $false
    try {
        $isDC = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole -ge 4
    }
    catch {
        Write-Log 'Unable to determine domain controller status; proceeding with promotion' -Level Warning
    }

    if ($isDC) {
        Write-Log 'Server is already a domain controller; skipping promotion' -Level Warning
    }
    elseif ($PSCmdlet.ShouldProcess($DomainName, 'Promote server to domain controller')) {
        foreach ($path in @($databasePath, $logPath, $sysvolPath)) {
            try {
                if (-not (Test-Path $path)) {
                    New-Item -ItemType Directory -Path $path -Force | Out-Null
                }
            }
            catch {
            }
        }

        Write-Log 'Creating detached promotion script process (non-blocking)'
        $promoScriptPath = Join-Path $logDir 'Promote-ADDSForest.ps1'
        $promoLogPath = Join-Path $logDir 'Promote-ADDSForest-Progress.log'
        $transcriptPath = Join-Path $logDir "Promote-ADDSForest-Transcript-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

        $promotionScript = @'
function Write-ProgressLog {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$ts] [Information] $Message" | Tee-Object -FilePath "${promoLogPath}" -Append | Out-Null
}
Write-ProgressLog 'Promotion script launched'
try {
    Import-Module ADDSDeployment -ErrorAction Stop
}
catch {
    $modulePath = Join-Path $env:WinDir 'System32\WindowsPowerShell\v1.0\Modules\ADDSDeployment'
    if (Test-Path $modulePath) {
        Import-Module $modulePath -ErrorAction Stop
    }
    else {
        Write-ProgressLog "ADDSDeployment module not found at $modulePath"
        throw "ADDSDeployment module not found at $modulePath"
    }
}
Start-Transcript -Path "${transcriptPath}" -Force | Out-Null
try {
    $plain = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${SafeModeAdminPasswordBase64}"))
    $dsrmSecure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    Write-ProgressLog 'Invoking Install-ADDSForest'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Install-ADDSForest -DomainName "${DomainName}" -DomainNetbiosName "${DomainNetBiosName}" -SafeModeAdministratorPassword $dsrmSecure -DatabasePath "${databasePath}" -LogPath "${logPath}" -SysvolPath "${sysvolPath}" -InstallDns:$true -CreateDnsDelegation:$false -NoRebootOnCompletion:$false -Force:$true -ErrorAction Stop -Verbose 4>&1
    $sw.Stop()
    Write-ProgressLog ("Install-ADDSForest returned after " + $sw.Elapsed.ToString())
    $json = $result | ConvertTo-Json -Depth 4
    Add-Content -Path "${promoLogPath}" -Value 'RESULT_JSON_START'
    Add-Content -Path "${promoLogPath}" -Value $json
    Add-Content -Path "${promoLogPath}" -Value 'RESULT_JSON_END'
    Write-ProgressLog 'Promotion succeeded; system will reboot shortly'
}
catch {
    Write-ProgressLog ("Promotion failed: " + $_.Exception.Message)
    Write-ProgressLog ("Full error: " + ($_ | Out-String))
    exit 1
}
Stop-Transcript | Out-Null
'@

        $promotionScript = $promotionScript.Replace('${promoLogPath}', $promoLogPath)
        $promotionScript = $promotionScript.Replace('${transcriptPath}', $transcriptPath)
        $promotionScript = $promotionScript.Replace('${SafeModeAdminPasswordBase64}', $SafeModeAdminPasswordBase64)
        $promotionScript = $promotionScript.Replace('${DomainName}', $DomainName)
        $promotionScript = $promotionScript.Replace('${DomainNetBiosName}', $DomainNetBiosName)
        $promotionScript = $promotionScript.Replace('${databasePath}', $databasePath)
        $promotionScript = $promotionScript.Replace('${logPath}', $logPath)
        $promotionScript = $promotionScript.Replace('${sysvolPath}', $sysvolPath)

        Set-Content -Path $promoScriptPath -Value $promotionScript -Force -Encoding UTF8
        Write-Log "Promotion script written to $promoScriptPath"

        $powershellPath = Join-Path $env:WinDir 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path $powershellPath)) {
            $powershellPath = 'PowerShell.exe'
        }

        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = $powershellPath
        $processStartInfo.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$promoScriptPath`""
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.RedirectStandardOutput = $true
        $processStartInfo.RedirectStandardError = $true

        $process = [System.Diagnostics.Process]::Start($processStartInfo)
        Write-Log "Detached process started (Id=$($process.Id))"

        Start-Sleep -Seconds 5
        if (Test-Path $promoLogPath) {
            Write-Log "Progress log created: $promoLogPath"
        }
        else {
            Write-Log 'Progress log not yet created; promotion script may still be initializing' -Level Warning
        }

        Write-Log 'Non-blocking promotion initiated via detached process; Run Command can now return'
    }

    Write-Log 'AD DS bootstrap completed successfully (promotion phase only)'
}
catch {
    Write-Log "AD DS bootstrap failed: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    throw
}