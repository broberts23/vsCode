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

    It 'New-PimActivationRequest returns PSCustomObject with requestId and status' {
        $obj = New-PimActivationRequest -RoleId 'role-123' -ResourceId 'res-456' -Justification 'test'
        $obj | Should -Not -BeNullOrEmpty
        $obj | Should -BeOfType 'System.Management.Automation.PSCustomObject'
    $obj.PSObject.Properties.Name | Should -Contain 'requestId'
    $obj.PSObject.Properties.Name | Should -Contain 'status'
    $obj.requestId | Should -Not -BeNullOrEmpty
    $obj.status | Should -Not -BeNullOrEmpty
    }
}