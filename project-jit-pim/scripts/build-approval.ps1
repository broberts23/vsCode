# Inputs via env:
# ROLE_IDS, RESOURCE_IDS, SUBSCRIPTION_ID, VAULT_NAME, GITHUB_WORKSPACE, GITHUB_OUTPUT, ASSIGNEE_OBJECT_ID, VAULT_RESOURCE_ID

try {
  $roles = ConvertFrom-Json $env:ROLE_IDS
} catch { $roles = @() }
try {
  $resources = ConvertFrom-Json $env:RESOURCE_IDS
} catch { $resources = @() }

function Set-StringArray([object]$value) {
  $list = @()
  if ($null -eq $value) { return $list }
  $items = if ($value -is [System.Array]) { @($value) } else { @($value) }
  foreach ($i in $items) {
    if ($null -ne $i) {
      $s = [string]$i
      if ($s -and $s.Trim() -ne '') { $list += $s }
    }
  }
  return ,$list
}

# Normalize to arrays of non-empty strings
$rolesArr = Set-StringArray $roles
$resourcesArr = Set-StringArray $resources

# Replace placeholder <AZURE_SUBSCRIPTION_ID> in resource IDs when a subscriptionId input is provided
$subscriptionId = $env:SUBSCRIPTION_ID
if (($null -ne $subscriptionId) -and ($subscriptionId -ne '')) {
  $tmp = @()
  foreach ($res in $resourcesArr) { $tmp += ($res -replace '<AZURE_SUBSCRIPTION_ID>', $subscriptionId) }
  $resourcesArr = $tmp
}

# Remove any entries that still contain the placeholder
$resourcesArr = @($resourcesArr | Where-Object { $_ -notmatch '<AZURE_SUBSCRIPTION_ID>' })

# Build pairing logic
$pairs = @()
$rolesCount = @($rolesArr).Count
$resourcesCount = @($resourcesArr).Count
if (($rolesCount -eq 1) -and ($resourcesCount -ge 1)) {
  foreach ($res in @($resourcesArr)) { $pairs += [pscustomobject]@{ RoleId = $rolesArr[0]; ResourceId = $res } }
} elseif (($resourcesCount -eq 1) -and ($rolesCount -ge 1)) {
  foreach ($r in @($rolesArr)) { $pairs += [pscustomobject]@{ RoleId = $r; ResourceId = $resourcesArr[0] } }
} elseif ($rolesCount -eq $resourcesCount) {
  for ($i = 0; $i -lt $rolesCount; $i++) { $pairs += [pscustomobject]@{ RoleId = $rolesArr[$i]; ResourceId = $resourcesArr[$i] } }
} else {
  foreach ($r in @($rolesArr)) { foreach ($res in @($resourcesArr)) { $pairs += [pscustomobject]@{ RoleId = $r; ResourceId = $res } } }
}

if (@($pairs).Count -lt 1) { throw 'No valid role/resource pairs to process (roleIds or resourceIds empty after filtering).' }

# Build table
$table = "| RoleId | RoleName | ResourceId | ResourceName | ResourceType | RequestId |`n|---|---|---|---|---|---|`n"
$requests = @()

Import-Module -Name (Join-Path $env:GITHUB_WORKSPACE 'project-jit-pim/scripts/PimAutomation.psm1')

foreach ($pair in $pairs) {
  $roleId = $pair.RoleId; $resourceId = $pair.ResourceId
  $req = New-PimActivationRequest -RoleId $roleId -ResourceId $resourceId -Justification 'CI requested activation'
  $requests += $req

  # Resolve role name and resource details (best-effort)
  $roleName = $roleId
  try {
    $rj = $null
    if ($roleId -match '^/') {
      $rjJson = az role definition show --id $roleId -o json 2>$null
    } elseif ($roleId -match '^[0-9a-fA-F\-]{36}$') {
      if (-not [string]::IsNullOrEmpty($subscriptionId)) {
        $fqId = "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleDefinitions/$roleId"
        $rjJson = az role definition show --id $fqId -o json 2>$null
      } else {
        $rjJson = az role definition list --query "[?roleName=='$roleId' || name=='$roleId'] | [0]" -o json 2>$null
      }
    } else {
      $rjJson = az role definition list --name "$roleId" -o json 2>$null
      if (-not $rjJson) { $rjJson = az role definition list --query "[?contains(roleName, '$roleId')] | [0]" -o json 2>$null }
    }
    if ($rjJson) { $rj = $rjJson | ConvertFrom-Json } else { $rj = $null }
    if ($rj -and $rj.roleName) { $roleName = $rj.roleName } elseif ($rj -and $rj.properties -and $rj.properties.roleName) { $roleName = $rj.properties.roleName }
  } catch { $rj = $null }

  $resName = $resourceId; $resType = ''
  try {
    $resj = az resource show --ids $resourceId -o json 2>$null | ConvertFrom-Json
    if ($resj) { $resName = $resj.name; $resType = $resj.type }
  } catch { }

  $escape = { param($s) if ($null -eq $s) { return '``' } else { return ('`' + ($s -replace '\|', '\\|') + '`') } }
  $rIdCell = & $escape $roleId
  $rNameCell = & $escape $roleName
  $resIdCell = & $escape $resourceId
  $resNameCell = & $escape $resName
  $resTypeCell = & $escape $resType

  $reqId = $req.requestId -or $req.id -or ([guid]::NewGuid()).Guid
  $reqIdCell = & $escape $reqId
  $table += "| $rIdCell | $rNameCell | $resIdCell | $resNameCell | $resTypeCell | $reqIdCell |`n"
}

# Export outputs
if ($env:GITHUB_OUTPUT) {
  Add-Content -Path $env:GITHUB_OUTPUT -Value "approvalTable<<EOF"
  Add-Content -Path $env:GITHUB_OUTPUT -Value $table
  Add-Content -Path $env:GITHUB_OUTPUT -Value "EOF"
  Add-Content -Path $env:GITHUB_OUTPUT -Value "assignee=$($env:ASSIGNEE_OBJECT_ID)"
  Add-Content -Path $env:GITHUB_OUTPUT -Value "vault=$($env:VAULT_RESOURCE_ID)"
} else {
  Write-Output "approvalTable:"; Write-Output $table
  Write-Output "assignee: $env:ASSIGNEE_OBJECT_ID"; Write-Output "vault: $env:VAULT_RESOURCE_ID"
}

Write-Output "::set-output name=approvalTable::$table"
