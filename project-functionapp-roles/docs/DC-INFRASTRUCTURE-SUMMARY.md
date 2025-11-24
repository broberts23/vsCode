# Domain Controller Infrastructure - Summary

## What Was Added

This update adds optional self-contained Active Directory Domain Services infrastructure to the password reset function app solution, enabling complete demo and development environments without requiring existing on-premises AD infrastructure.

## New Resources

### Bicep Infrastructure (`infra/main.bicep`)

1. **Virtual Network** (`Microsoft.Network/virtualNetworks`)

   - Address space: 10.0.0.0/16
   - **DomainControllerSubnet**: 10.0.1.0/24 (hosts DC VM)
   - **FunctionAppSubnet**: 10.0.2.0/24 (for VNet integration)

2. **Network Security Group** (`Microsoft.Network/networkSecurityGroups`)

   - RDP access (port 3389)
   - AD DS protocols (LDAP, LDAPS, Kerberos, DNS, SMB, Global Catalog)

3. **Public IP Address** (`Microsoft.Network/publicIPAddresses`)

   - Standard SKU with static allocation
   - DNS label for easy access

4. **Network Interface** (`Microsoft.Network/networkInterfaces`)

   - Static private IP: 10.0.1.4
   - Attached to DomainControllerSubnet
   - Public IP for remote access

5. **Virtual Machine** (`Microsoft.Compute/virtualMachines`)

   - Windows Server 2022 Datacenter
   - Size: Standard_D2s_v3 (2 vCPU, 8 GB RAM)
   - OS disk: Premium SSD (128 GB)
   - Data disk: Premium SSD (32 GB for AD DS database)
   - Boot diagnostics enabled

6. **Custom Script Extension** (`Microsoft.Compute/virtualMachines/extensions`)
   - Installs AD-Domain-Services Windows feature
   - Formats data disk for AD DS database
   - Promotes server to domain controller
   - Configures DNS service

### Parameters

New parameters added to `main.bicep` and parameter files:

| Parameter                | Type         | Description                  | Default |
| ------------------------ | ------------ | ---------------------------- | ------- |
| `deployDomainController` | bool         | Enable/disable DC deployment | false   |
| `vmAdminUsername`        | string       | VM administrator username    | -       |
| `vmAdminPassword`        | securestring | VM administrator password    | -       |
| `domainName`             | string       | FQDN for the domain          | -       |
| `domainNetBiosName`      | string       | NetBIOS name for the domain  | -       |

### Scripts

1. **`Bootstrap-ADDSDomain.ps1`**

   - Comprehensive AD DS installation and configuration script
   - Installs Windows feature (AD-Domain-Services)
   - Formats data disk for NTDS database
   - Promotes server to domain controller
   - Creates OU, service account, and test users
   - Grants password reset permissions to service account
   - PowerShell 7.4 compatible with full error handling
   - Reference: https://learn.microsoft.com/powershell/module/addsdeployment/install-addsforest?view=windowsserver2022-ps

2. **`Configure-ADPostPromotion.ps1`**

   - Post-promotion configuration script
   - Creates `FunctionAppResources` OU
   - Creates `svc-functionapp` service account with password reset permissions
   - Creates test users (testuser1, testuser2, testuser3)
   - Designed for Azure VM Run Command execution
   - Reference: https://learn.microsoft.com/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps

3. **`Deploy-Complete.ps1`**
   - End-to-end deployment orchestration
   - Creates resource group
   - Deploys Bicep template
   - Waits for DC promotion completion
   - Runs post-configuration script automatically
   - Outputs deployment results
   - Reference: https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest

### Documentation

1. **`docs/DOMAIN-CONTROLLER-SETUP.md`**

   - Complete setup guide for DC infrastructure
   - Deployment instructions with Azure CLI and PowerShell examples
   - Post-configuration steps
   - Verification procedures
   - Networking details
   - Security best practices
   - Cost considerations
   - Troubleshooting guide

2. **`docs/DEPLOYMENT-CHECKLIST.md`**

   - Step-by-step deployment checklist
   - Parameter preparation
   - Deployment validation
   - Testing procedures
   - Troubleshooting common issues
   - Cleanup instructions

3. **Updated `README.md`**
   - Added reference to domain controller setup guide
   - New network connectivity option (Option 1: Self-contained DC)
   - Deployment instructions updated

## What Gets Created

When `deployDomainController: true`:

### Infrastructure

- Windows Server 2022 VM (dc-{baseName}-{environment})
- Virtual network with two subnets
- NSG with AD DS traffic rules
- Public IP for remote access
- Network interface with static private IP (10.0.1.4)

### Active Directory

- Domain: `contoso.local` (or custom domain name)
- NetBIOS: `CONTOSO` (or custom NetBIOS name)
- DNS service configured automatically

### Organizational Unit

- **FunctionAppResources**: Container for all demo resources

### Service Account

- **Name**: `svc-functionapp`
- **UPN**: `svc-functionapp@contoso.local`
- **Purpose**: Function app AD authentication
- **Permissions**: Password reset extended right on all user objects
- **Properties**: Password never expires, cannot change password

### Test Users

| Username  | Display Name | Initial Password | Purpose                   |
| --------- | ------------ | ---------------- | ------------------------- |
| testuser1 | Test User 1  | InitialP@ss123!  | Password reset validation |
| testuser2 | Test User 2  | InitialP@ss123!  | Password reset validation |
| testuser3 | Test User 3  | InitialP@ss123!  | Password reset validation |

## Deployment Flow

1. **Bicep Deployment**

   - Creates VNet, NSG, Public IP, NIC
   - Creates VM with Windows Server 2022
   - Attaches Custom Script Extension

2. **Custom Script Extension**

   - Installs AD-Domain-Services role
   - Formats data disk (F:\ for NTDS)
   - Runs `Install-ADDSForest` cmdlet
   - Reboots server (automatic)
   - **Duration**: ~15-20 minutes

3. **Post-Promotion Configuration**

   - Waits for AD Web Services availability
   - Creates OU: FunctionAppResources
   - Creates service account with password reset permission
   - Creates test users
   - **Duration**: ~2-5 minutes

4. **Function App Configuration**
   - Update environment variables with DC FQDN/IP
   - Store service account password in Key Vault
   - Enable VNet integration (if using Premium plan)

## Usage Examples

### Deploy with Domain Controller

```powershell
./scripts/Deploy-Complete.ps1 `
    -Environment dev `
    -ResourceGroupName 'rg-pwdreset-dev' `
    -Location 'eastus' `
    -DeployDomainController `
    -VmAdminPassword (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force) `
    -ServiceAccountPassword (ConvertTo-SecureString 'SvcP@ss123!' -AsPlainText -Force)
```

### Deploy without Domain Controller (Existing AD)

```powershell
./scripts/Deploy-Complete.ps1 `
    -Environment dev `
    -ResourceGroupName 'rg-pwdreset-dev' `
    -Location 'eastus'
```

### Manual Bicep Deployment

```bash
az deployment group create \
  --resource-group rg-pwdreset-dev \
  --template-file infra/main.bicep \
  --parameters @infra/parameters.dev.json \
  --parameters vmAdminPassword='P@ssw0rd123!'
```

## Cost Estimate (Monthly, East US)

| Resource  | SKU/Size          | Estimated Cost  |
| --------- | ----------------- | --------------- |
| VM        | Standard_D2s_v3   | ~$96.00         |
| OS Disk   | Premium SSD 128GB | ~$9.60          |
| Data Disk | Premium SSD 32GB  | ~$4.80          |
| Public IP | Standard Static   | ~$3.60          |
| VNet      | Standard          | $0.00           |
| **Total** |                   | **~$114/month** |

**Notes**:

- Costs based on pay-as-you-go pricing
- Shut down VM when not in use to save costs
- Consider Azure Dev/Test pricing if eligible

## Security Considerations

### Default Configuration (Demo/Dev)

- Public IP attached for easy access
- RDP open to internet (restrict in production)
- Service account with password never expires

### Production Recommendations

1. **Remove Public IP**: Use Azure Bastion or VPN Gateway
2. **Restrict NSG**: Limit RDP to specific IP ranges or remove entirely
3. **Use Azure AD Domain Services**: Managed PaaS alternative
4. **Enable Monitoring**: Azure Monitor, Security Center, and Sentinel
5. **Rotate Credentials**: Service account password rotation policy
6. **Managed Identity**: Configure function app with managed identity for Key Vault

## Conditional Deployment

All DC resources use conditional deployment (`if (deployDomainController)`):

```bicep
resource dcVm 'Microsoft.Compute/virtualMachines@2024-03-01' = if (deployDomainController) {
  // VM configuration
}
```

Setting `deployDomainController: false` omits all DC resources from deployment, allowing the solution to work with existing AD infrastructure via VNet integration or Hybrid Connection.

## Testing the Setup

### Verify Domain Controller

```powershell
# RDP to VM public IP
Get-ADDomainController -Identity dc01
Get-ADUser -Filter * | Select-Object Name, SamAccountName
Get-ADOrganizationalUnit -Filter "Name -eq 'FunctionAppResources'"
```

### Test Password Reset

```powershell
$headers = @{ Authorization = "Bearer $token" }
$body = @{ samAccountName = 'testuser1' } | ConvertTo-Json

Invoke-RestMethod `
    -Uri 'https://func-pwdreset-dev.azurewebsites.net/api/ResetUserPassword' `
    -Method Post `
    -Headers $headers `
    -Body $body `
    -ContentType 'application/json'
```

## References

- **Bicep Documentation**: https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview
- **Install-ADDSForest**: https://learn.microsoft.com/powershell/module/addsdeployment/install-addsforest?view=windowsserver2022-ps
- **New-ADUser**: https://learn.microsoft.com/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps
- **Azure Virtual Machines**: https://learn.microsoft.com/azure/virtual-machines/windows/overview
- **Custom Script Extension**: https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-windows
- **Azure Virtual Networks**: https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview
