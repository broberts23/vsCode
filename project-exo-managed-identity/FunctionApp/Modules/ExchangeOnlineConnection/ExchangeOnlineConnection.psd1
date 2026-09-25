@{
    RootModule        = 'ExchangeOnlineConnection.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a7c3e1f2-9b4d-4e8a-b1c6-5d2f8a0e3b79'
    Author            = 'project-exo-managed-identity'
    Description       = 'Process-wide SemaphoreSlim gate for Exchange Online managed-identity connect and refresh.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Initialize-ExchangeOnlineConnection'
        'Assert-ExchangeOnlineConnection'
    )
    PrivateData       = @{
        PSData = @{
            Tags = @('ExchangeOnline', 'ManagedIdentity', 'AzureFunctions')
        }
    }
}
