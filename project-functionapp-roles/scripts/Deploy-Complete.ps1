#!/usr/bin/env pwsh
#Requires -Version 7.4

<#
.SYNOPSIS
    Comprehensive deployment script for the password reset function app with optional domain controller.

.DESCRIPTION
    This script orchestrates the complete deployment of the password reset function app infrastructure,
    including optional domain controller deployment, service account configuration, and validation.

.PARAMETER Environment
    Target environment (dev, test, prod).

.PARAMETER ResourceGroupName
    Name of the resource group to deploy to.

.PARAMETER Location
    Azure region for deployment (e.g., 'eastus').

.PARAMETER DeployDomainController
    Deploy a self-contained Windows Server domain controller with AD DS.

.PARAMETER VmAdminPassword
    Password for the domain controller VM administrator account (required if DeployDomainController is $true).

.PARAMETER ServiceAccountPassword
    Password for the AD service account (required if DeployDomainController is $true).

.PARAMETER SkipPostConfiguration
    Skip post-deployment configuration (service account and test user creation).

.EXAMPLE
    .\Deploy-Complete.ps1 -Environment dev -ResourceGroupName rg-pwdreset-dev -Location eastus

.EXAMPLE
    .\Deploy-Complete.ps1 -Environment dev -ResourceGroupName rg-pwdreset-dev -Location eastus -DeployDomainController -VmAdminPassword (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force) -ServiceAccountPassword (ConvertTo-SecureString 'SvcP@ss123!' -AsPlainText -Force)

.NOTES
    Author: GitHub Copilot
    Requires: Az PowerShell module, Bicep CLI

.LINK
    https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest

.LINK
    https://learn.microsoft.com/azure/azure-resource-manager/bicep/deploy-cli
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('dev', 'test', 'prod')]
    [string]$Environment,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Location,

    [Parameter(Mandatory = $false)]
    [switch]$DeployDomainController,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$VmAdminUsername,

    [Parameter(Mandatory = $false)]
    [securestring]$VmAdminPassword,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceAccountUsername,

    [Parameter(Mandatory = $false)]
    [securestring]$ServiceAccountPassword,

    [Parameter(Mandatory = $false)]
    [switch]$SkipPostConfiguration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$infraDir = Join-Path (Split-Path -Parent $scriptDir) 'infra'
$parametersFile = Join-Path $infraDir "parameters.$Environment.json"
$bicepFile = Join-Path $infraDir 'main.bicep'

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
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

function Test-Prerequisites {
    [CmdletBinding()]
    param()

    Write-Log "Checking prerequisites..."

    # Check Az module
    if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
        throw "Az.Resources module not found. Install with: Install-Module -Name Az -Scope CurrentUser"
    }

    # Check Bicep CLI
    try {
        $null = bicep --version
        Write-Log "Bicep CLI found" -Level Success
    }
    catch {
        throw "Bicep CLI not found. Install from: https://learn.microsoft.com/azure/azure-resource-manager/bicep/install"
    }

    # Check parameters file
    if (-not (Test-Path $parametersFile)) {
        throw "Parameters file not found: $parametersFile"
    }

    # Check Bicep file
    if (-not (Test-Path $bicepFile)) {
        throw "Bicep file not found: $bicepFile"
    }

    Write-Log "Prerequisites validated" -Level Success
}

function New-RandomPassword {
    [CmdletBinding()]
    [OutputType([securestring])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(12, 128)]
        [int]$Length = 20
    )

    # Generate a complex password meeting Azure VM (Windows) complexity requirements
    # Use a conservative special character set to avoid API rejections and escape issues
    $upper = 1..1 | ForEach-Object { [char](Get-Random -Minimum 65 -Maximum 91) } # A-Z
    $lower = 1..1 | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) } # a-z
    $digit = 1..1 | ForEach-Object { [char](Get-Random -Minimum 48 -Maximum 58) } # 0-9
    $specialChars = '!@#$%^&*()-_=+[]{}:,.?'
    $special = 1..1 | ForEach-Object { $specialChars[(Get-Random -Minimum 0 -Maximum $specialChars.Length)] }

    $pool = @()
    $pool += (65..90 + 97..122 + 48..57) | ForEach-Object { [char]$_ }
    $pool += $specialChars.ToCharArray()

    $remainingCount = [Math]::Max(($Length - 4), 0)
    $remaining = if ($remainingCount -gt 0) { 1..$remainingCount | ForEach-Object { $pool[(Get-Random -Minimum 0 -Maximum $pool.Count)] } } else { @() }

    $chars = @($upper + $lower + $digit + $special + $remaining)
    $passwordPlain = -join ($chars | Sort-Object { Get-Random })

    # Final sanity checks: length and category coverage
    if ($passwordPlain.Length -lt 8 -or $passwordPlain.Length -gt 123) {
        # Regenerate with default length if out of bounds
        return (New-RandomPassword -Length 20)
    }

    return (ConvertTo-SecureString -String $passwordPlain -AsPlainText -Force)
}

function New-ResourceGroupIfNotExists {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Location
    )

    $rg = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    
    if ($null -eq $rg) {
        if ($PSCmdlet.ShouldProcess($Name, "Create resource group")) {
            Write-Log "Creating resource group: $Name"
            New-AzResourceGroup -Name $Name -Location $Location -Tag @{
                Environment = $Environment
                ManagedBy   = 'Bicep'
                Purpose     = 'PasswordResetFunctionApp'
            } | Out-Null
            Write-Log "Resource group created" -Level Success
        }
    }
    else {
        Write-Log "Resource group already exists: $Name" -Level Information
    }
}

function Invoke-BicepDeployment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$TemplateFile,

        [Parameter(Mandatory = $true)]
        [string]$ParameterFile,

        [Parameter(Mandatory = $false)]
        [hashtable]$AdditionalParameters = @{}
    )

    if ($PSCmdlet.ShouldProcess($ResourceGroupName, "Deploy Bicep template")) {
        Write-Log "Starting Bicep deployment to resource group: $ResourceGroupName"
        Write-Log "Template: $TemplateFile"
        Write-Log "Parameters: $ParameterFile"

        $deploymentParams = @{
            ResourceGroupName     = $ResourceGroupName
            TemplateFile          = $TemplateFile
            TemplateParameterFile = $ParameterFile
            Verbose               = $VerbosePreference -eq 'Continue'
        }

        # Add additional parameters
        foreach ($key in $AdditionalParameters.Keys) {
            $deploymentParams[$key] = $AdditionalParameters[$key]
        }

        try {
            $deployment = New-AzResourceGroupDeployment @deploymentParams

            if ($deployment.ProvisioningState -eq 'Succeeded') {
                Write-Log "Deployment succeeded" -Level Success
                return $deployment
            }
            else {
                throw "Deployment failed with state: $($deployment.ProvisioningState)"
            }
        }
        catch {
            Write-Log "Deployment failed: $_" -Level Error
            throw
        }
    }
}

function Invoke-DomainControllerPromotion {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [string]$DomainNetBiosName,

        [Parameter(Mandatory = $true)]
        [securestring]$VmAdminPassword
    )

    if ($PSCmdlet.ShouldProcess($VmName, "Promote to AD DS domain controller")) {
        Write-Log "Waiting for VM to be ready for promotion..." -Level Information
        
        # Wait for VM to be in running state
        $timeout = 300
        $elapsed = 0
        $checkInterval = 15
        
        while ($elapsed -lt $timeout) {
            $vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VmName -Status
            $powerState = ($vm.Statuses | Where-Object { $_.Code -like 'PowerState/*' }).Code
            
            if ($powerState -eq 'PowerState/running') {
                Write-Log "VM is running and ready" -Level Success
                break
            }
            
            Start-Sleep -Seconds $checkInterval
            $elapsed += $checkInterval
        }

        if ($elapsed -ge $timeout) {
            throw "Timeout waiting for VM to be ready"
        }

        # Invoke AD DS promotion via Run Command
        Write-Log "Invoking AD DS promotion via Run Command (background job)..." -Level Information
        $bootstrapScript = Get-Content (Join-Path $scriptDir 'Bootstrap-ADDSDomain.ps1') -Raw
        $plainPassword = [System.Net.NetworkCredential]::new('', $VmAdminPassword).Password
        $passwordBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($plainPassword))

        # Run command as background job since the VM will reboot and the command won't return normally
        $job = Invoke-AzVMRunCommand `
            -ResourceGroupName $ResourceGroupName `
            -VMName $VmName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $bootstrapScript `
            -Parameter @{
            DomainName                  = $DomainName
            DomainNetBiosName           = $DomainNetBiosName
            SafeModeAdminPasswordBase64 = $passwordBase64
        } `
            -AsJob

        Write-Log "AD DS promotion command sent as background job; waiting for promotion to begin..." -Level Success
        
        # Give the promotion a moment to start
        Start-Sleep -Seconds 30
        Write-Log "Promotion should be in progress; VM will reboot when complete" -Level Information
    }
}

function Invoke-DomainControllerPostConfig {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$VmName,

        [Parameter(Mandatory = $true)]
        [string]$DomainName,

        [Parameter(Mandatory = $true)]
        [securestring]$ServiceAccountPassword,

        [Parameter(Mandatory = $false)]
        [string]$ServiceAccountName
    )

    if ($PSCmdlet.ShouldProcess($VmName, "Configure AD post-promotion")) {
        Write-Log "Waiting for domain controller promotion to complete..."
        Write-Log "Monitoring for reboot cycle and AD Web Services availability..."

        $timeout = 1800  # 30 minutes
        $elapsed = 0
        $checkInterval = 60
        $initialBootTime = $null
        $rebootDetected = $false
        $rebootWindowObserved = $false

        # Get initial boot time
        Write-Log "Querying initial VM boot time..." -Level Information
        $bootTimeScript = 'Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime'
        $bootResult = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName -CommandId 'RunPowerShellScript' -ScriptString $bootTimeScript -ErrorAction SilentlyContinue
        if ($bootResult -and $bootResult.Value[0].Message) {
            try {
                $initialBootTime = [DateTime]::Parse(($bootResult.Value[0].Message).Trim())
                Write-Log "Initial boot time: $($initialBootTime.ToString('u'))" -Level Information
            }
            catch {
                Write-Log "Failed to parse initial boot time; raw: $($bootResult.Value[0].Message)" -Level Warning
            }
        }
        else {
            Write-Log "Unable to query initial boot time; proceeding without reboot detection." -Level Warning
        }

        while ($elapsed -lt $timeout) {
            try {
                # Query current boot time
                $currentBootResult = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName -CommandId 'RunPowerShellScript' -ScriptString $bootTimeScript -ErrorAction SilentlyContinue
                $currentBootTime = $null
                if ($currentBootResult -and $currentBootResult.Value[0].Message) {
                    try {
                        $currentBootTime = [DateTime]::Parse(($currentBootResult.Value[0].Message).Trim())
                    }
                    catch {
                        Write-Log "Failed to parse current boot time; raw: $($currentBootResult.Value[0].Message)" -Level Warning
                    }
                }
                else {
                    # During reboot the Run Command often fails; treat this transient failure as reboot window
                    $rebootWindowObserved = $true
                }

                if ($initialBootTime -and $currentBootTime -and ($currentBootTime -ne $initialBootTime)) {
                    Write-Log "VM reboot detected (boot time changed)!" -Level Success
                    $rebootDetected = $true
                }
                elseif ($rebootWindowObserved -and $currentBootTime) {
                    # We observed a failure (likely reboot), and now boot time is available again; mark reboot detected
                    if ($initialBootTime -and ($currentBootTime -ne $initialBootTime)) {
                        Write-Log "VM reboot detected after transient unavailability!" -Level Success
                    }
                    else {
                        Write-Log "VM likely rebooted (transient unavailability observed)." -Level Success
                    }
                    $rebootDetected = $true
                }

                if ($rebootDetected) {
                    Write-Log "Checking AD Web Services readiness..." -Level Information
                    $testScript = 'try { Import-Module ActiveDirectory -ErrorAction Stop; Get-ADDomain -ErrorAction Stop | Out-Null; exit 0 } catch { exit 1 }'
                    $testResult = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName -CommandId 'RunPowerShellScript' -ScriptString $testScript -ErrorAction SilentlyContinue
                    if ($testResult -and $testResult.Value[0].Message -notlike '*exit code*1*') {
                        Write-Log "AD Web Services is ready; proceeding with post-configuration" -Level Success
                        break
                    }
                }
                else {
                    Write-Log "Waiting for VM reboot (boot time change)..." -Level Information
                }
            }
            catch {
                Write-Log "Error checking VM boot time or AD status: $($_.Exception.Message)" -Level Warning
            }
            Start-Sleep -Seconds $checkInterval
            $elapsed += $checkInterval
        }

        if ($elapsed -ge $timeout) {
            Write-Log "Timeout waiting for domain controller reboot and AD readiness; manual configuration may be required" -Level Warning
            return
        }

        # Run post-configuration script
        Write-Log "Running AD post-configuration script via Run Command..."
        
        $postConfigScript = Get-Content (Join-Path $scriptDir 'Configure-ADPostPromotion.ps1') -Raw
        $password = [System.Net.NetworkCredential]::new('', $ServiceAccountPassword).Password

        $result = Invoke-AzVMRunCommand `
            -ResourceGroupName $ResourceGroupName `
            -VMName $VmName `
            -CommandId 'RunPowerShellScript' `
            -ScriptString $postConfigScript `
            -Parameter @{
            DomainName             = $DomainName
            ServiceAccountPassword = $password
            ServiceAccountName     = $ServiceAccountName
        }

        if ($result.Value[0].Message -like '*completed successfully*') {
            Write-Log "AD post-configuration completed successfully" -Level Success
        }
        else {
            Write-Log "AD post-configuration may have issues; check VM logs" -Level Warning
            Write-Log $result.Value[0].Message
        }
    }
}

# Main execution
try {
    Write-Log "Starting deployment for environment: $Environment" -Level Information

    # Validate prerequisites
    Test-Prerequisites

    # Ensure authenticated to Azure
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $context) {
        Write-Log "Not authenticated to Azure; connecting..." -Level Warning
        Connect-AzAccount
    }
    else {
        Write-Log "Authenticated as: $($context.Account.Id)" -Level Information
    }

    # Create resource group
    New-ResourceGroupIfNotExists -Name $ResourceGroupName -Location $Location

    # Prepare deployment parameters
    $additionalParams = @{}

    if ($DeployDomainController) {
        $additionalParams['deployDomainController'] = $true

        # VM admin username/password: allow overrides, else default username in Bicep and auto-generated password here
        if ($PSBoundParameters.ContainsKey('VmAdminUsername') -and [string]::IsNullOrWhiteSpace($VmAdminUsername) -eq $false) {
            $additionalParams['vmAdminUsername'] = $VmAdminUsername
        }

        if ($null -eq $VmAdminPassword) {
            Write-Log "VmAdminPassword not provided; generating a strong random password" -Level Warning
            $VmAdminPassword = New-RandomPassword -Length 24
        }
        # Pass SecureString for secure Bicep parameters (dynamic parameter binding expects SecureString)
        $additionalParams['vmAdminPassword'] = $VmAdminPassword

        # Service account username/password: allow overrides, else use default name and auto-generate password
        if ($PSBoundParameters.ContainsKey('ServiceAccountUsername') -and [string]::IsNullOrWhiteSpace($ServiceAccountUsername) -eq $false) {
            # Convert to SecureString as Bicep marks username secure
            $additionalParams['adServiceAccountUsername'] = (ConvertTo-SecureString -String $ServiceAccountUsername -AsPlainText -Force)
        }

        if ($null -eq $ServiceAccountPassword) {
            Write-Log "ServiceAccountPassword not provided; generating a strong random password" -Level Warning
            $ServiceAccountPassword = New-RandomPassword -Length 24
        }
        # Pass SecureString for secure Bicep parameter
        $additionalParams['serviceAccountPassword'] = $ServiceAccountPassword
    }

    # Deploy infrastructure
    $deployment = Invoke-BicepDeployment `
        -ResourceGroupName $ResourceGroupName `
        -TemplateFile $bicepFile `
        -ParameterFile $parametersFile `
        -AdditionalParameters $additionalParams

    # Output deployment results
    Write-Log "Deployment outputs:" -Level Success
    foreach ($output in $deployment.Outputs.GetEnumerator()) {
        Write-Log "  $($output.Key): $($output.Value.Value)" -Level Information
    }

    # Domain controller configuration
    if ($DeployDomainController) {
        $parameters = Get-Content $parametersFile | ConvertFrom-Json
        $domainName = $parameters.parameters.domainName.value
        $domainNetBiosName = $parameters.parameters.domainNetBiosName.value
        $baseName = $parameters.parameters.baseName.value
        $dcVmName = "$baseName-dc-$Environment"

        # Step 1: Promote to domain controller via Run Command
        Invoke-DomainControllerPromotion `
            -ResourceGroupName $ResourceGroupName `
            -VmName $dcVmName `
            -DomainName $domainName `
            -DomainNetBiosName $domainNetBiosName `
            -VmAdminPassword $VmAdminPassword

        # Step 2: Post-configuration (OU, service account, test users)
        if (-not $SkipPostConfiguration) {
            Invoke-DomainControllerPostConfig `
                -ResourceGroupName $ResourceGroupName `
                -VmName $dcVmName `
                -DomainName $domainName `
                -ServiceAccountPassword $ServiceAccountPassword `
                -ServiceAccountName $ServiceAccountUsername
        }
    }

    Write-Log "Deployment completed successfully!" -Level Success

}
catch {
    Write-Log "Deployment failed: $_" -Level Error
    Write-Log "Exception: $($_.Exception.Message)" -Level Error
    exit 1
}
