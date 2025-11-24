# Domain Controller Setup Guide

This guide explains how to deploy and configure the self-contained Active Directory Domain Services environment for the password reset function app demo.

## Overview

The Bicep infrastructure includes optional domain controller (DC) resources that create a complete AD DS environment for testing and demonstration purposes. This allows you to run the solution without requiring an existing on-premises Active Directory infrastructure.

## Architecture

When `deployDomainController` is set to `true`, the deployment creates:

- **Virtual Network (VNet)**: 10.0.0.0/16 address space
  - **DomainControllerSubnet**: 10.0.1.0/24 (hosts the DC VM)
  - **FunctionAppSubnet**: 10.0.2.0/24 (for VNet integration)
- **Network Security Group (NSG)**: Rules for RDP and AD DS traffic
- **Windows Server 2022 VM**: Standard_D2s_v3 with data disk for AD DS database
- **Public IP**: For remote access to the DC
- **Custom Script Extension**: Bootstraps AD DS role installation and domain promotion

## Prerequisites

- Azure subscription with permissions to create VMs and networking resources
- PowerShell 7.4 or later (for running post-configuration scripts)
- Azure CLI or Azure PowerShell module (for deployment)

## Deployment

### 1. Update Parameters

Edit `infra/parameters.dev.json` (or your target environment):

```json
{
  "deployDomainController": {
    "value": true
  },
  "vmAdminUsername": {
    "value": "azureadmin"
  },
  "vmAdminPassword": {
    "value": "YourSecureP@ssw0rd!"
  },
  "domainName": {
    "value": "contoso.local"
  },
  "domainNetBiosName": {
    "value": "CONTOSO"
  },
  "domainController": {
    "value": "dc01.contoso.local"
  }
}
```

**Security Note**: Do NOT commit passwords to source control. Use Azure Key Vault references or pass as secure parameters during deployment.

### 2. Deploy Infrastructure

Using Azure CLI:

```bash
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters @infra/parameters.dev.json \
  --parameters vmAdminPassword='YourSecureP@ssw0rd!'
```

Using Azure PowerShell:

```powershell
New-AzSubscriptionDeployment `
  -Location 'eastus' `
  -TemplateFile 'infra/main.bicep' `
  -TemplateParameterFile 'infra/parameters.dev.json' `
  -vmAdminPassword (ConvertTo-SecureString 'YourSecureP@ssw0rd!' -AsPlainText -Force)
```

### 3. Wait for Domain Promotion

The Custom Script Extension installs AD DS and promotes the server to a domain controller. This process takes approximately **15-20 minutes** and includes an automatic reboot.

Monitor the deployment:

```bash
# Check VM extension status
az vm extension list --resource-group rg-pwdreset-dev --vm-name dc-pwdreset-dev --query "[].{Name:name,Status:provisioningState}" -o table
```

### 4. Post-Promotion Configuration

After the DC promotion completes, run the post-configuration script to create the service account and test users:

```powershell
# From your local machine with Azure CLI installed
$serviceAccountPassword = ConvertTo-SecureString 'SvcP@ss123!' -AsPlainText -Force

az vm run-command invoke `
  --resource-group 'rg-pwdreset-dev' `
  --name 'dc-pwdreset-dev' `
  --command-id 'RunPowerShellScript' `
  --scripts @scripts/Configure-ADPostPromotion.ps1 `
  --parameters "DomainName=contoso.local" "ServiceAccountPassword=$serviceAccountPassword"
```

Alternatively, RDP to the VM and run the script locally:

```powershell
# On the domain controller VM
.\Configure-ADPostPromotion.ps1 `
  -DomainName 'contoso.local' `
  -ServiceAccountPassword (ConvertTo-SecureString 'SvcP@ss123!' -AsPlainText -Force)
```

## What Gets Created

### Organizational Unit

- **FunctionAppResources**: OU containing all demo resources

### Service Account

- **Name**: `svc-functionapp`
- **Purpose**: Used by the function app to authenticate to AD and reset passwords
- **Permissions**: Extended right to reset passwords for all users in the domain
- **Properties**: Enabled, password never expires, cannot change password

### Test Users

Three test users are created for validation:

| Username  | Display Name | Initial Password | Location                                    |
| --------- | ------------ | ---------------- | ------------------------------------------- |
| testuser1 | Test User 1  | InitialP@ss123!  | OU=FunctionAppResources,DC=contoso,DC=local |
| testuser2 | Test User 2  | InitialP@ss123!  | OU=FunctionAppResources,DC=contoso,DC=local |
| testuser3 | Test User 3  | InitialP@ss123!  | OU=FunctionAppResources,DC=contoso,DC=local |

## Network Configuration

### Security Rules

The NSG allows:

- **RDP (3389)**: From any source (restrict in production)
- **AD DS Protocols**: From VirtualNetwork service tag
  - LDAP (389)
  - LDAPS (636)
  - Global Catalog (3268/3269)
  - Kerberos (88)
  - DNS (53)
  - SMB (445)

### VNet Integration

The function app can be configured for VNet integration to reach the domain controller on the private network. This requires:

1. Function app Premium plan (not Consumption) **OR** Regional VNet Integration
2. Configuration of VNet integration pointing to `FunctionAppSubnet`

## Verification

### Test Domain Controller Connectivity

From the Azure Portal or using Run Command:

```powershell
# Verify domain controller role
Get-ADDomainController -Identity dc01

# List domain users
Get-ADUser -Filter * | Select-Object Name, SamAccountName

# Verify service account
Get-ADUser -Identity svc-functionapp -Properties Description, PasswordNeverExpires

# Test DNS resolution
Resolve-DnsName contoso.local
```

### Test Password Reset Permission

```powershell
# Verify ACL contains password reset permission
$acl = Get-Acl -Path "AD:\DC=contoso,DC=local"
$acl.Access | Where-Object { $_.IdentityReference -like "*svc-functionapp*" }
```

## Cost Considerations

Running the domain controller VM incurs costs:

- **Standard_D2s_v3**: ~$96/month (pay-as-you-go, East US)
- **Premium SSD Disks**: ~$10/month (128GB OS + 32GB data)
- **Public IP**: ~$3.60/month
- **VNet**: No charge for basic VNet and subnet configuration

**Recommendation**: Use Azure Dev/Test pricing if eligible, or shut down the VM when not in use.

## Security Best Practices

### Production Considerations

The default configuration is designed for demos and development. For production:

1. **Remove Public IP**: Use Azure Bastion or VPN Gateway for access
2. **Restrict NSG Rules**: Limit RDP to specific IP ranges or disable entirely
3. **Use Managed Identities**: Configure function app with managed identity and avoid storing service account passwords
4. **Enable Azure AD Domain Services**: Consider Azure AD DS instead of IaaS VMs for production workloads
5. **Implement Monitoring**: Enable Azure Monitor, Log Analytics, and Security Center
6. **Backup Domain Controller**: Configure Azure Backup for VM and AD DS state

### Password Management

- Store `vmAdminPassword` in Azure Key Vault
- Rotate service account password regularly
- Use Azure Key Vault for `adServiceAccountPassword` parameter in function app
- Enable MFA for VM administrator accounts

## Troubleshooting

### Domain Promotion Fails

Check the Custom Script Extension logs:

```bash
az vm extension list --resource-group rg-pwdreset-dev --vm-name dc-pwdreset-dev
```

RDP to the VM and check:

- `C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\`
- Event Viewer → Windows Logs → System (look for AD DS installation events)

### Service Account Creation Fails

Common issues:

- **AD Web Services not running**: Wait 5-10 minutes after promotion
- **Password complexity**: Ensure password meets domain policy (default: 7+ characters, complexity enabled)
- **Permissions**: Run script with Domain Admin credentials

### Function App Cannot Reach DC

- Verify VNet integration is configured and enabled
- Check NSG rules allow traffic from FunctionAppSubnet
- Test DNS resolution: `Resolve-DnsName contoso.local` from function app (Kudu console)
- Verify domain controller firewall rules

## Cleanup

To remove all domain controller resources:

1. Set `deployDomainController` to `false` in parameters file
2. Redeploy (resources will be removed due to conditional deployment)

Or manually delete:

```bash
# Delete VM and associated resources
az vm delete --resource-group rg-pwdreset-dev --name dc-pwdreset-dev --yes
az disk delete --resource-group rg-pwdreset-dev --name dc-pwdreset-dev-osdisk --yes
az disk delete --resource-group rg-pwdreset-dev --name dc-pwdreset-dev-datadisk --yes
az network nic delete --resource-group rg-pwdreset-dev --name nic-dc-pwdreset-dev
az network public-ip delete --resource-group rg-pwdreset-dev --name pip-dc-pwdreset-dev
az network vnet delete --resource-group rg-pwdreset-dev --name vnet-pwdreset-dev
az network nsg delete --resource-group rg-pwdreset-dev --name nsg-dc-pwdreset-dev
```

## References

- [Install-ADDSForest (Microsoft Learn)](https://learn.microsoft.com/powershell/module/addsdeployment/install-addsforest?view=windowsserver2022-ps)
- [New-ADUser (Microsoft Learn)](https://learn.microsoft.com/powershell/module/activedirectory/new-aduser?view=windowsserver2022-ps)
- [Azure Virtual Machines Overview](https://learn.microsoft.com/azure/virtual-machines/windows/overview)
- [Azure Virtual Network Overview](https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview)
- [Custom Script Extension for Windows](https://learn.microsoft.com/azure/virtual-machines/extensions/custom-script-windows)
