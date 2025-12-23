@{
    RootModule = 'GovernanceAutomation.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'd8a00ae0-72a4-49a7-8bd7-ec4a3a363e4d'
    Author = 'Ben'
    CompanyName = ''
    Copyright = ''
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Get-Policy',
        'Get-DedupeKey',
        'Test-AndSetDedupe',
        'Get-ManagedIdentityAccessToken',
        'New-GovernanceWorkItem'
    )
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
}
