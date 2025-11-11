@{
    RootModule        = 'WorkloadIdentityTools.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '4e3b6e8b-2b0d-4d7d-9e3d-111111111111'
    Author            = 'Workload Identity Toolkit'
    CompanyName       = 'Contoso'
    Copyright         = '(c) 2025 Workload Identity Toolkit. MIT License.'
    PowerShellVersion = '7.4'
    Description       = 'Toolkit for discovering and remediating risky Microsoft Entra workload identities.'
    FunctionsToExport = @(
        'Connect-WiGraph',
        'Get-WiRiskyServicePrincipal',
        'Get-WiApplicationCredentialInventory',
        'Get-WiServicePrincipalPrivilegedAssignments',
        'Get-WiHighPrivilegeAppPermissions',
        'Get-WiTenantConsentSettings',
        'New-WiFederatedCredential',
        'Add-WiApplicationCertificateCredential'
    )
    PrivateData       = @{ }
}
