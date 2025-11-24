# PowerShell Gallery module dependencies for Azure Functions
# https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-powershell#dependency-management
#
# Specifies module versions using semantic versioning
# https://semver.org/
#
# Note: System.IdentityModel.Tokens.Jwt is a .NET assembly, not a PowerShell module.
# It must be packaged as DLLs in the 'bin' folder for deployment.
# Download from: https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt/

@{
    # No PowerShell Gallery dependencies for this project
    # .NET assemblies are loaded via bin/System.IdentityModel.Tokens.Jwt.dll
}
