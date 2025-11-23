param(
  [Parameter(Mandatory)][string]$StorageAccountName,
  [Parameter(Mandatory)][string]$ResourceGroup,
  [int]$PastDays = 10,
  [int]$FutureDays = 10,
  [int]$PerDayPerPath = 2
)

Write-Host "Seeding storage account '$StorageAccountName' in resource group '$ResourceGroup'"

try { Connect-AzAccount } catch { Write-Warning "Identity auth failed; ensure you are logged in." }

$sa = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroup -ErrorAction Stop
$ctx = $sa.Context

$containers = @("imports", "exports", "audit", "telemetry", "samples")
$paths = @("signin/entra", "signin/activedirectory", "logs/system", "logs/application")

foreach ($c in $containers) {
  try { New-AzStorageContainer -Name $c -Context $ctx -Permission Off -ErrorAction SilentlyContinue | Out-Null } catch {}
  foreach ($offset in (-1 * $PastDays)..$FutureDays) {
    $stamp = (Get-Date).AddDays($offset).ToUniversalTime().ToString('yyyyMMddHHmmss')
    foreach ($p in $paths) {
      for ($i = 1; $i -le $PerDayPerPath; $i++) {
        $blobName = "$p/$stamp-$i.json"
        $tmp = New-TemporaryFile
        Set-Content -Path $tmp -Encoding UTF8 -Value $stamp
        try {
          Set-AzStorageBlobContent -File $tmp -Container $c -Blob $blobName -Context $ctx -Force -ErrorAction Stop | Out-Null
        }
        catch {}
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
      }
    }
  }
}

Write-Host "Seeding complete." -ForegroundColor Green
