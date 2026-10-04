# PowerShell Gallery module dependencies for Azure Functions
# https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell#dependency-management
#
# ExchangeOnlineManagement 3.10.0+ requires PowerShell 7.6 (.NET 10).
# Pin major.minor; managed dependency resolves the latest matching patch.

@{
    'ExchangeOnlineManagement' = '3.5.0'
}
