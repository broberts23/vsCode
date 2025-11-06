Describe 'PimAutomation module' {
    BeforeEach {
        $env:PIM_AUTOMATION_SKIP_GRAPH = '1'
        $modulePath = Join-Path $PSScriptRoot '..' 'scripts' 'PimAutomation.psm1'
        Remove-Module PimAutomation -ErrorAction SilentlyContinue
        Import-Module $modulePath -Force -ErrorAction Stop | Out-Null
    }

    AfterEach {
        Remove-Module PimAutomation -ErrorAction SilentlyContinue
        Remove-Item Env:PIM_AUTOMATION_SKIP_GRAPH -ErrorAction SilentlyContinue
    }

    It 'Resolve-PimRoleResourcePairs duplicates single role across multiple resources' {
        $pairs = Resolve-PimRoleResourcePairs -RoleIdsJson '["role-123"]' -ResourceIdsJson '["res-1","res-2"]'
        $pairs | Should -Not -BeNullOrEmpty
        ($pairs | Measure-Object).Count | Should -Be 2
        $pairs[0].RoleId | Should -Be 'role-123'
        $pairs[1].RoleId | Should -Be 'role-123'
        $pairs[0].ResourceId | Should -Be 'res-1'
        $pairs[1].ResourceId | Should -Be 'res-2'
    }
}