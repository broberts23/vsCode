#!/usr/bin/env pwsh
#Requires -Version 7.4

using namespace System.Net

param($Request, $TriggerMetadata)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'LegacyRemotingHelpers.psm1') -Force

try {
    $clientPrincipalHeader = $Request.Headers['X-MS-CLIENT-PRINCIPAL']
    if (-not $clientPrincipalHeader) {
        throw 'Missing X-MS-CLIENT-PRINCIPAL header.'
    }

    $principal = Get-ClientPrincipal -HeaderValue $clientPrincipalHeader
    $requiredRole = if ([string]::IsNullOrWhiteSpace($env:REQUIRED_ROLE)) {
        'Role.LegacyCommand.Invoke'
    }
    else {
        $env:REQUIRED_ROLE
    }

    if (-not (Test-RoleClaim -Principal $principal -RequiredRole $requiredRole)) {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::Forbidden
                Headers = @{ 'Content-Type' = 'application/json' }
                Body = (@{
                        error = 'Forbidden'
                        message = "Caller is missing required role '$requiredRole'."
                    } | ConvertTo-Json)
            })
        return
    }

    $requestBody = if ($Request.Body -is [string]) {
        $Request.Body | ConvertFrom-Json -ErrorAction Stop
    }
    elseif ($Request.Body -is [hashtable]) {
        [pscustomobject]$Request.Body
    }
    else {
        $Request.Body
    }

    $scriptText = if ($requestBody.PSObject.Properties['scriptBlock']) { [string]$requestBody.scriptBlock } else { '' }
    $arguments = if ($requestBody.PSObject.Properties['arguments'] -and $requestBody.arguments) { [hashtable]$requestBody.arguments } else { @{} }
    $computerName = if ($requestBody.PSObject.Properties['computerName'] -and $requestBody.computerName) {
        [string]$requestBody.computerName
    }
    else {
        [string]$env:MANAGEMENT_HOST_FQDN
    }

    if ([string]::IsNullOrWhiteSpace($scriptText)) {
        throw 'scriptBlock is required in the request body.'
    }

    if ([string]::IsNullOrWhiteSpace($computerName)) {
        throw 'MANAGEMENT_HOST_FQDN is not configured.'
    }

    $port = if ([string]::IsNullOrWhiteSpace($env:MANAGEMENT_HOST_PORT)) { 5986 } else { [int]$env:MANAGEMENT_HOST_PORT }
    $credential = Get-FunctionJumpboxCredential
    $certificate = Get-FunctionJumpboxCertificate

    $invokeParameters = @{
        ComputerName = $computerName
        Port = $port
        Credential = $credential
        ExpectedCertificate = $certificate
        ScriptText = $scriptText
        Arguments = $arguments
    }
    $result = Invoke-LegacyRemoteScriptBlock @invokeParameters

    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Headers = @{ 'Content-Type' = 'application/json' }
            Body = (@{
                    status = 'Succeeded'
                    remoteComputer = $result.remote.computerName
                    remoteIdentity = $result.remote.identity
                    output = @($result.remote.output)
                    tls = $result.tls
                } | ConvertTo-Json -Depth 6)
        })
}
catch {
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Headers = @{ 'Content-Type' = 'application/json' }
            Body = (@{
                    error = 'RequestFailed'
                    message = $_.Exception.Message
                } | ConvertTo-Json)
        })
}