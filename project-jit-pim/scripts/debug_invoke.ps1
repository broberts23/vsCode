Import-Module Pester -ErrorAction Stop -Verbose:$false
$modulePath = '/home/ben/vsCode/project-jit-pim/scripts/PimAutomation.psm1'
$mod = Import-Module $modulePath -Force -PassThru -ErrorAction Stop -Verbose:$false

Write-Output "Imported module: $($mod.Name)"

InModuleScope -ModuleName $mod.Name {
    $pairs = Resolve-PimRoleResourcePairs -RoleIdsJson '["role-123"]' -ResourceIdsJson '["/subscriptions/0000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/sample"]'
    Write-Output "Resolved pairs:`n$($pairs | Format-Table -AutoSize | Out-String)"
}
