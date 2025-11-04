Import-Module Pester -ErrorAction Stop
$modulePath = '/home/ben/vsCode/project-jit-pim/scripts/PimAutomation.psm1'
$mod = Import-Module $modulePath -Force -PassThru -ErrorAction Stop

Write-Output "Imported module: $($mod.Name)"

InModuleScope -ModuleName $mod.Name {
    Mock -CommandName Get-GraphAccessToken -MockWith { return $null }
    Mock -CommandName Invoke-RestMethod -MockWith { return @{ id = 'stub-id'; status = 'Pending'; createdDateTime = (Get-Date).ToString() } }

    try {
        $result = New-PimActivationRequest -RoleId 'role-123' -ResourceId 'res-456' -Justification 'test'
        Write-Output "Function returned:`n$result | Format-List | Out-String"
    }
    catch {
        Write-Output "Caught error:`n$($_ | Out-String)"
        Write-Output "Exception ToString:`n$($_.Exception.ToString())"
        Write-Output "Exception details:`n$($_.Exception | Format-List -Force | Out-String)"
    }
}
