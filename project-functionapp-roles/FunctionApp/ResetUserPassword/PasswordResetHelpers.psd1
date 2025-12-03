#!/usr/bin/env pwsh
#Requires -Version 7.4

@{
    ModuleVersion        = '1.0.0'
    GUID                 = 'f8a3c4d2-9e7b-4f1a-8c6d-5e2a9b7f4c1d'
    Author               = 'Function App'
    CompanyName          = 'Organization'
    Copyright            = '(c) 2024. All rights reserved.'
    Description          = 'Helper module for JWT validation and password operations in Azure Function App'
    PowerShellVersion    = '7.4'
    
    RequiredModules      = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Users'; ModuleVersion = '2.0.0' }
    )
    
    RequiredAssemblies   = @(
        'System.IdentityModel.Tokens.Jwt'
    )
    
    FunctionsToExport    = @(
        'Test-JwtToken'
        'Test-RoleClaim'
        'New-SecurePassword'
        'Set-UserPassword'
    )
    
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    
    PrivateData          = @{
        PSData = @{
            Tags       = @('Azure', 'Functions', 'EntraID', 'JWT', 'Password')
            ProjectUri = ''
        }
    }
}
