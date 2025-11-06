#!/usr/bin/env pwsh
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
Simple sanity-check for the table-generation logic used in the GitHub Actions workflow.
This script builds a few sample rows (including pipes and newlines) and prints the markdown table.
#>

function ConvertTo-MarkdownCell {
    param(
        [string]$s
    )
    if ($null -eq $s) {
        return '``'
    }
    # Replace problematic characters: backticks -> HTML entity, pipes escaped, newlines collapsed to space, trim
    $escaped = $s -replace '`', '&#96;'
    $escaped = $escaped -replace '\|', '\\|'
    $escaped = $escaped -replace '\r\n|\n|\r', ' '
    $escaped = $escaped.Trim()
    return ('`' + $escaped + '`')
}

$rows = @(
    @{ roleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'; roleName = 'Key Vault Secrets Officer'; resourceId = '/subscriptions/0000/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/my|vault'; resName = 'my|vault'; resType = 'Microsoft.KeyVault/vaults' },
    @{ roleId = 'role-2'; roleName = 'Role With `backtick` and | pipe'; resourceId = '/subscriptions/0000/resourceGroups/rg2/providers/Microsoft.Service/thing'; resName = "Name`nWithNewline"; resType = 'Custom.Type' }
)

$header = "| roleId | roleName | resourceId | resourceName | resourceType |`n|---|---|---|---|---|`n"
$table = $header

foreach ($row in $rows) {
    $rIdCell = ConvertTo-MarkdownCell $row.roleId
    $rNameCell = ConvertTo-MarkdownCell $row.roleName
    $resIdCell = ConvertTo-MarkdownCell $row.resourceId
    $resNameCell = ConvertTo-MarkdownCell $row.resName
    $resTypeCell = ConvertTo-MarkdownCell $row.resType

    $table += "| $rIdCell | $rNameCell | $resIdCell | $resNameCell | $resTypeCell |`n"
}

Write-Output $table

Write-Output "`n--- Diagnostics ---`n"
foreach ($row in $rows) {
    $fields = @{
        roleId = $row.roleId
        roleName = $row.roleName
        resourceId = $row.resourceId
        resourceName = $row.resName
    }
    foreach ($k in $fields.Keys) {
        $v = $fields[$k]
        $hasNewline = $false
        if ($null -ne $v) { $hasNewline = ($v -match "\r\n|\n|\r") }
        $hasPipe = $false
        if ($null -ne $v) { $hasPipe = ($v -match '\|') }
        $hasBacktick = $false
        if ($null -ne $v) { $hasBacktick = ($v -match '`') }
        $escaped = ConvertTo-MarkdownCell $v
    Write-Output ($k + ': containsNewline=' + $hasNewline + ', containsPipe=' + $hasPipe + ', containsBacktick=' + $hasBacktick + ' -> escaped=' + $escaped)
    }
    Write-Output "---"
}

exit 0
