#!/usr/bin/env pwsh
#Requires -Version 7.4

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('dev', 'test', 'prod')]
    [string]$Environment,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Location = 'eastus',

    [Parameter()]
    [string]$ParameterFile,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientId,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$VmAdminUsername,

    [Parameter()]
    [securestring]$VmAdminPassword,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountName = 'svc-legacyjump',

    [Parameter()]
    [securestring]$ServiceAccountPassword,

    [Parameter()]
    [switch]$PublishFunctionApp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path $PSScriptRoot -Parent
$script:ScriptDirectory = $PSScriptRoot
$script:ProjectRoot = $projectRoot
$script:InfraDirectory = Join-Path $projectRoot 'infra'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'Information' { 'White' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function ConvertTo-PlainText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [securestring]$SecureString
    )

    return [System.Net.NetworkCredential]::new('', $SecureString).Password
}

function Test-IsPlaceholderValue {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $true
    }

    return $Value -match '^(YOUR_|REPLACE_|<)' -or $Value -match 'PLACEHOLDER'
}

function Get-ParameterFileObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ResolvedParameterFile
    )

    if (-not (Test-Path $ResolvedParameterFile)) {
        throw "Parameter file not found: $ResolvedParameterFile"
    }

    return Get-Content -Path $ResolvedParameterFile -Raw | ConvertFrom-Json -ErrorAction Stop
}

function Get-ParameterFileValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ParameterObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        $DefaultValue = $null
    )

    if ($null -eq $ParameterObject.parameters) {
        return $DefaultValue
    }

    $property = $ParameterObject.parameters.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $DefaultValue
    }

    if ($null -eq $property.Value) {
        return $DefaultValue
    }

    return $property.Value.value
}

function Resolve-SecureParameterValue {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ParameterObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [securestring]$ProvidedValue
    )

    if ($ProvidedValue) {
        return $ProvidedValue
    }

    $fileValue = [string](Get-ParameterFileValue -ParameterObject $ParameterObject -Name $Name)
    if (Test-IsPlaceholderValue -Value $fileValue) {
        throw "Provide -$Name or replace the placeholder value in the parameter file before running Deploy-Complete.ps1."
    }

    return ConvertTo-SecureString -String $fileValue -AsPlainText -Force
}

function Resolve-PlainParameterValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$ParameterObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string]$ProvidedValue,

        [Parameter()]
        [string]$DefaultValue
    )

    if (-not [string]::IsNullOrWhiteSpace($ProvidedValue)) {
        return $ProvidedValue
    }

    $fileValue = [string](Get-ParameterFileValue -ParameterObject $ParameterObject -Name $Name -DefaultValue $DefaultValue)
    if (Test-IsPlaceholderValue -Value $fileValue) {
        return $DefaultValue
    }

    return $fileValue
}

function Get-DeploymentOutputValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)]
        $Deployment,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if (-not $Deployment.Outputs -or -not $Deployment.Outputs.ContainsKey($Name)) {
        throw "Deployment output '$Name' was not found."
    }

    return $Deployment.Outputs[$Name].Value
}

function Invoke-VmRunCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$ScriptString,

        [Parameter()]
        [hashtable]$Parameters = @{},

        [Parameter()]
        [switch]$AsJob,

        [Parameter()]
        [switch]$AllowFailure
    )

    $invokeParameters = @{
        ResourceGroupName = $ResourceGroupName
        VMName = $VmName
        CommandId = 'RunPowerShellScript'
        ScriptString = $ScriptString
    }

    if ($Parameters.Count -gt 0) {
        $invokeParameters.Parameter = $Parameters
    }

    if ($AsJob) {
        $invokeParameters.AsJob = $true
    }

    if ($AllowFailure) {
        $invokeParameters.ErrorAction = 'SilentlyContinue'
    }

    return Invoke-AzVMRunCommand @invokeParameters
}

function Get-RunCommandMessage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        $RunCommandResult
    )

    if ($null -eq $RunCommandResult -or $null -eq $RunCommandResult.Value) {
        return ''
    }

    return (($RunCommandResult.Value | ForEach-Object { $_.Message }) -join [Environment]::NewLine).Trim()
}

function Wait-ForVmPowerState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter()]
        [ValidateSet('PowerState/running', 'PowerState/stopped', 'PowerState/deallocated')]
        [string]$ExpectedState = 'PowerState/running',

        [Parameter()]
        [int]$TimeoutSeconds = 600,

        [Parameter()]
        [int]$CheckIntervalSeconds = 15
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Status
        $powerState = ($vm.Statuses | Where-Object { $_.Code -like 'PowerState/*' } | Select-Object -First 1).Code
        if ($powerState -eq $ExpectedState) {
            return
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
        $elapsed += $CheckIntervalSeconds
    }

    throw "Timeout waiting for VM '$VmName' to reach state '$ExpectedState'."
}

function Get-VmBootTime {
    [CmdletBinding()]
    [OutputType([Nullable[datetime]])]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName
    )

    $script = 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime'

    try {
        $result = Invoke-VmRunCommand -ResourceGroupName $ResourceGroupName -VmName $VmName -ScriptString $script -AllowFailure
        $message = Get-RunCommandMessage -RunCommandResult $result
        if ([string]::IsNullOrWhiteSpace($message)) {
            return $null
        }

        return [datetime]::Parse($message.Split([Environment]::NewLine)[0].Trim())
    }
    catch {
        return $null
    }
}

function Wait-ForVmReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$ReadinessScript,

        [Parameter()]
        [switch]$RequireReboot,

        [Parameter()]
        [int]$TimeoutSeconds = 1800,

        [Parameter()]
        [int]$CheckIntervalSeconds = 60
    )

    $initialBootTime = Get-VmBootTime -ResourceGroupName $ResourceGroupName -VmName $VmName
    $elapsed = 0
    $rebootObserved = -not $RequireReboot
    $transientFailureObserved = $false

    while ($elapsed -lt $TimeoutSeconds) {
        try {
            $currentBootTime = Get-VmBootTime -ResourceGroupName $ResourceGroupName -VmName $VmName
            if ($RequireReboot -and -not $currentBootTime) {
                $transientFailureObserved = $true
            }

            if ($RequireReboot) {
                if ($initialBootTime -and $currentBootTime -and $currentBootTime -ne $initialBootTime) {
                    $rebootObserved = $true
                }
                elseif ($transientFailureObserved -and $currentBootTime) {
                    $rebootObserved = $true
                }
            }

            if ($rebootObserved) {
                $readinessResult = Invoke-VmRunCommand -ResourceGroupName $ResourceGroupName -VmName $VmName -ScriptString $ReadinessScript -AllowFailure
                $readinessMessage = Get-RunCommandMessage -RunCommandResult $readinessResult
                if ($readinessResult -and $readinessMessage -notlike '*exit code: 1*' -and $readinessMessage -notlike '*exit code 1*') {
                    return
                }
            }
        }
        catch {
            $transientFailureObserved = $true
        }

        Start-Sleep -Seconds $CheckIntervalSeconds
        $elapsed += $CheckIntervalSeconds
    }

    throw "Timeout waiting for VM '$VmName' readiness."
}

function Get-PrimaryPrivateIpAddress {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName
    )

    $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName
    $primaryNicReference = $vm.NetworkProfile.NetworkInterfaces | Select-Object -First 1
    if (-not $primaryNicReference) {
        throw "VM '$VmName' does not have a network interface."
    }

    $nicName = Split-Path -Path $primaryNicReference.Id -Leaf
    $nic = Get-AzNetworkInterface -ResourceGroupName $ResourceGroupName -Name $nicName
    return $nic.IpConfigurations[0].PrivateIpAddress
}

function Invoke-DomainControllerPromotion {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetBiosName,

        [Parameter(Mandatory)]
        [securestring]$VmAdminPassword
    )

    if ($PSCmdlet.ShouldProcess($VmName, 'Promote to AD DS domain controller')) {
        Write-Log "Waiting for $VmName to be running before promotion..."
        Wait-ForVmPowerState -ResourceGroupName $ResourceGroupName -VmName $VmName

        $bootstrapScript = Get-Content (Join-Path $script:ScriptDirectory 'Bootstrap-ADDSDomain.ps1') -Raw
        $passwordBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-PlainText -SecureString $VmAdminPassword)))

        $null = Invoke-VmRunCommand -ResourceGroupName $ResourceGroupName -VmName $VmName -ScriptString $bootstrapScript -Parameters @{
            DomainName = $DomainName
            DomainNetBiosName = $DomainNetBiosName
            SafeModeAdminPasswordBase64 = $passwordBase64
        } -AsJob

        Write-Log 'AD DS promotion command submitted as a background job.' -Level Success
        Start-Sleep -Seconds 30
    }
}

function Invoke-DomainControllerPostConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [securestring]$ServiceAccountPassword,

        [Parameter(Mandatory)]
        [string]$ServiceAccountName
    )

    if ($PSCmdlet.ShouldProcess($VmName, 'Configure AD post-promotion')) {
        Write-Log 'Waiting for domain controller reboot and AD readiness...'
        $readinessScript = "try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -Identity '$DomainName' -ErrorAction Stop | Out-Null; exit 0 } catch { exit 1 }"
        Wait-ForVmReadiness -ResourceGroupName $ResourceGroupName -VmName $VmName -ReadinessScript $readinessScript -RequireReboot

        $postConfigScript = Get-Content (Join-Path $script:ScriptDirectory 'Configure-ADPostPromotion.ps1') -Raw
        $result = Invoke-VmRunCommand -ResourceGroupName $ResourceGroupName -VmName $VmName -ScriptString $postConfigScript -Parameters @{
            DomainName = $DomainName
            ServiceAccountName = $ServiceAccountName
            ServiceAccountPassword = (ConvertTo-PlainText -SecureString $ServiceAccountPassword)
        }

        $message = Get-RunCommandMessage -RunCommandResult $result
        if (-not [string]::IsNullOrWhiteSpace($message)) {
            Write-Log $message -Level Success
        }
    }
}

function Invoke-ManagementVmDomainJoin {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainJoinUsername,

        [Parameter(Mandatory)]
        [securestring]$DomainJoinPassword,

        [Parameter(Mandatory)]
        [string]$DnsServer
    )

    if ($PSCmdlet.ShouldProcess($VmName, 'Join management VM to domain')) {
        Write-Log "Waiting for $VmName to be running before domain join..."
        Wait-ForVmPowerState -ResourceGroupName $ResourceGroupName -VmName $VmName

        $joinScript = Get-Content (Join-Path $script:ScriptDirectory 'Join-ManagementVmToDomain.ps1') -Raw
        $null = Invoke-VmRunCommand -ResourceGroupName $ResourceGroupName -VmName $VmName -ScriptString $joinScript -Parameters @{
            DomainName = $DomainName
            DomainJoinUsername = $DomainJoinUsername
            DomainJoinPassword = (ConvertTo-PlainText -SecureString $DomainJoinPassword)
            DnsServer = $DnsServer
        } -AsJob

        Write-Log 'Domain join command submitted as a background job.' -Level Success
        Start-Sleep -Seconds 30

        $readinessScript = "`$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem; if (`$computerSystem.PartOfDomain -and `$computerSystem.Domain -ieq '$DomainName') { exit 0 } else { exit 1 }"
        Wait-ForVmReadiness -ResourceGroupName $ResourceGroupName -VmName $VmName -ReadinessScript $readinessScript -RequireReboot
    }
}

function ConvertFrom-RunCommandJson {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message
    )

    $trimmed = $Message.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw 'Run Command did not return JSON output.'
    }

    $startIndex = $trimmed.IndexOf('{')
    $endIndex = $trimmed.LastIndexOf('}')
    if ($startIndex -lt 0 -or $endIndex -lt $startIndex) {
        throw "Unable to find JSON payload in Run Command output: $trimmed"
    }

    return $trimmed.Substring($startIndex, ($endIndex - $startIndex + 1)) | ConvertFrom-Json -ErrorAction Stop
}

function Invoke-ManagementVmWinRmConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory)]
        [string]$VmName,

        [Parameter(Mandatory)]
        [string]$ComputerFqdn,

        [Parameter(Mandatory)]
        [string]$KeyVaultName
    )

    if ($PSCmdlet.ShouldProcess($VmName, 'Configure WinRM HTTPS and store certificate')) {
        $scriptText = Get-Content (Join-Path $script:ScriptDirectory 'Configure-ManagementWinRmHttps.ps1') -Raw
        $result = Invoke-VmRunCommand -ResourceGroupName $ResourceGroupName -VmName $VmName -ScriptString $scriptText -Parameters @{
            ComputerFqdn = $ComputerFqdn
        }

        $message = Get-RunCommandMessage -RunCommandResult $result
        $certificateInfo = ConvertFrom-RunCommandJson -Message $message
        $secret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name 'JUMPBOX-WINRM-CERT-CER' -SecretValue (ConvertTo-SecureString -String $certificateInfo.CertificateBase64 -AsPlainText -Force)

        Write-Log "Stored WinRM HTTPS certificate in Key Vault secret '$($secret.Name)'." -Level Success
        return $certificateInfo
    }
}

try {
    Write-Log "Starting complete jumpbox deployment for environment '$Environment'."

    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        throw 'Connect-AzAccount before running this script.'
    }

    $resolvedParameterFile = if ($ParameterFile) { $ParameterFile } else { Join-Path $script:InfraDirectory "parameters.$Environment.json" }
    $parameterObject = Get-ParameterFileObject -ResolvedParameterFile $resolvedParameterFile

    $vmAdminUsernameToUse = Resolve-PlainParameterValue -ParameterObject $parameterObject -Name 'vmAdminUsername' -ProvidedValue $VmAdminUsername -DefaultValue 'azureadmin'
    $vmAdminPasswordToUse = Resolve-SecureParameterValue -ParameterObject $parameterObject -Name 'vmAdminPassword' -ProvidedValue $VmAdminPassword
    $serviceAccountPasswordToUse = Resolve-SecureParameterValue -ParameterObject $parameterObject -Name 'serviceAccountPassword' -ProvidedValue $ServiceAccountPassword
    $tenantIdToUse = Resolve-PlainParameterValue -ParameterObject $parameterObject -Name 'tenantId' -ProvidedValue $TenantId
    $clientIdToUse = Resolve-PlainParameterValue -ParameterObject $parameterObject -Name 'clientId' -ProvidedValue $ClientId
    $domainName = [string](Get-ParameterFileValue -ParameterObject $parameterObject -Name 'domainName' -DefaultValue 'contoso.local')
    $domainNetBiosName = [string](Get-ParameterFileValue -ParameterObject $parameterObject -Name 'domainNetBiosName' -DefaultValue 'CONTOSO')

    $parameterOverrides = @{
        tenantId = $tenantIdToUse
        clientId = $clientIdToUse
        vmAdminUsername = $vmAdminUsernameToUse
        vmAdminPassword = (ConvertTo-PlainText -SecureString $vmAdminPasswordToUse)
        serviceAccountPassword = (ConvertTo-PlainText -SecureString $serviceAccountPasswordToUse)
    }

    $deployInfrastructureParameters = @{
        Environment = $Environment
        ResourceGroupName = $ResourceGroupName
        Location = $Location
        ParameterFile = $resolvedParameterFile
        ParameterOverrides = $parameterOverrides
        PassThru = $true
    }

    $deployment = & (Join-Path $script:ScriptDirectory 'Deploy-Infrastructure.ps1') @deployInfrastructureParameters
    if (-not $deployment) {
        throw 'Infrastructure deployment did not return a deployment result.'
    }

    $domainControllerVmName = [string](Get-DeploymentOutputValue -Deployment $deployment -Name 'domainControllerVmName')
    $managementVmName = [string](Get-DeploymentOutputValue -Deployment $deployment -Name 'managementVmName')
    $managementVmFqdn = [string](Get-DeploymentOutputValue -Deployment $deployment -Name 'managementVmFqdn')
    $functionAppName = [string](Get-DeploymentOutputValue -Deployment $deployment -Name 'functionAppName')
    $keyVaultName = [string](Get-DeploymentOutputValue -Deployment $deployment -Name 'keyVaultName')

    Invoke-DomainControllerPromotion -ResourceGroupName $ResourceGroupName -VmName $domainControllerVmName -DomainName $domainName -DomainNetBiosName $domainNetBiosName -VmAdminPassword $vmAdminPasswordToUse
    Invoke-DomainControllerPostConfig -ResourceGroupName $ResourceGroupName -VmName $domainControllerVmName -DomainName $domainName -ServiceAccountPassword $serviceAccountPasswordToUse -ServiceAccountName $ServiceAccountName

    $domainControllerPrivateIp = Get-PrimaryPrivateIpAddress -ResourceGroupName $ResourceGroupName -VmName $domainControllerVmName
    $domainJoinUsername = '{0}\{1}' -f $domainNetBiosName, $ServiceAccountName

    Invoke-ManagementVmDomainJoin -ResourceGroupName $ResourceGroupName -VmName $managementVmName -DomainName $domainName -DomainJoinUsername $domainJoinUsername -DomainJoinPassword $serviceAccountPasswordToUse -DnsServer $domainControllerPrivateIp
    $null = Invoke-ManagementVmWinRmConfiguration -ResourceGroupName $ResourceGroupName -VmName $managementVmName -ComputerFqdn $managementVmFqdn -KeyVaultName $keyVaultName

    if ($PublishFunctionApp) {
        & (Join-Path $script:ScriptDirectory 'Deploy-FunctionApp.ps1') -FunctionAppName $functionAppName
    }

    Write-Log 'Complete jumpbox deployment finished.' -Level Success
}
catch {
    Write-Log "Deployment failed: $($_.Exception.Message)" -Level Error
    throw
}