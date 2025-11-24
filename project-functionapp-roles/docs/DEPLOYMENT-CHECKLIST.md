# Deployment Checklist

Complete deployment checklist for the password reset function app with self-contained domain controller.

## Prerequisites ✓

- [ ] Azure subscription with Contributor access
- [ ] PowerShell 7.4 or later installed
- [ ] Az PowerShell module installed
- [ ] Bicep CLI installed
- [ ] Repository cloned locally

## Step 1: Prepare Parameters ✓

- [ ] Copy `infra/parameters.dev.json` if needed
- [ ] Update `tenantId` with your Entra ID tenant
- [ ] Update `clientId` with your app registration ID
- [ ] Set `deployDomainController` to `true` for demo environment
- [ ] Define `vmAdminUsername` (e.g., `azureadmin`)
- [ ] Choose secure passwords for `vmAdminPassword` and service account
- [ ] Set `domainName` (e.g., `contoso.local`)
- [ ] Set `domainNetBiosName` (e.g., `CONTOSO`)
- [ ] Verify `location` is your preferred Azure region

## Step 2: Deploy Infrastructure ✓

Option A: Using the comprehensive deployment script (recommended):

```powershell
./scripts/Deploy-Complete.ps1 `
    -Environment dev `
    -ResourceGroupName 'rg-pwdreset-dev' `
    -Location 'eastus' `
    -DeployDomainController `
    -VmAdminPassword (ConvertTo-SecureString 'YourVmP@ssw0rd!' -AsPlainText -Force) `
    -ServiceAccountPassword (ConvertTo-SecureString 'YourSvcP@ssw0rd!' -AsPlainText -Force)
```

Option B: Manual deployment:

```powershell
# Connect to Azure
Connect-AzAccount

# Create resource group
New-AzResourceGroup -Name 'rg-pwdreset-dev' -Location 'eastus'

# Deploy Bicep template
New-AzResourceGroupDeployment `
    -ResourceGroupName 'rg-pwdreset-dev' `
    -TemplateFile 'infra/main.bicep' `
    -TemplateParameterFile 'infra/parameters.dev.json' `
    -vmAdminPassword (ConvertTo-SecureString 'YourVmP@ssw0rd!' -AsPlainText -Force)
```

**Expected Duration**: 15-25 minutes (includes VM deployment and AD DS promotion with reboot)

## Step 3: Verify Domain Controller ✓

- [ ] Check deployment succeeded in Azure Portal
- [ ] Verify VM `dc-<baseName>-<env>` is running
- [ ] Check Custom Script Extension completed successfully
- [ ] Verify domain promotion (this includes automatic reboot)

**Check VM Status**:

```powershell
Get-AzVM -ResourceGroupName 'rg-pwdreset-dev' -Name 'dc-pwdreset-dev' -Status
```

**Check Extension Status**:

```powershell
Get-AzVMExtension -ResourceGroupName 'rg-pwdreset-dev' -VMName 'dc-pwdreset-dev'
```

## Step 4: Post-Promotion Configuration ✓

If using `Deploy-Complete.ps1`, this runs automatically. Otherwise, run manually:

```powershell
$serviceAccountPassword = ConvertTo-SecureString 'YourSvcP@ssw0rd!' -AsPlainText -Force

# Option A: Via Azure Run Command (from local machine)
$postConfigScript = Get-Content './scripts/Configure-ADPostPromotion.ps1' -Raw
Invoke-AzVMRunCommand `
    -ResourceGroupName 'rg-pwdreset-dev' `
    -VMName 'dc-pwdreset-dev' `
    -CommandId 'RunPowerShellScript' `
    -ScriptString $postConfigScript `
    -Parameter @{ DomainName = 'contoso.local'; ServiceAccountPassword = $serviceAccountPassword }

# Option B: RDP to VM and run locally
# RDP to VM public IP, then run:
.\Configure-ADPostPromotion.ps1 -DomainName 'contoso.local' -ServiceAccountPassword $serviceAccountPassword
```

**What This Creates**:

- OU: `FunctionAppResources`
- Service Account: `svc-functionapp` (with password reset permission)
- Test Users: `testuser1`, `testuser2`, `testuser3` (password: `InitialP@ss123!`)

## Step 5: Verify AD Configuration ✓

RDP to the domain controller VM and verify:

```powershell
# List domain users
Get-ADUser -Filter * | Select-Object Name, SamAccountName

# Verify service account
Get-ADUser -Identity svc-functionapp -Properties Description, PasswordNeverExpires

# Verify test users
Get-ADUser -Filter "SamAccountName -like 'testuser*'"

# Verify ACL (password reset permission)
$acl = Get-Acl -Path "AD:\DC=contoso,DC=local"
$acl.Access | Where-Object { $_.IdentityReference -like "*svc-functionapp*" }
```

## Step 6: Configure Function App ✓

- [ ] Navigate to function app in Azure Portal
- [ ] Go to **Settings → Configuration**
- [ ] Verify environment variables:
  - `AD_DOMAIN_CONTROLLER`: `dc-<baseName>-<env>.contoso.local` (or private IP `10.0.1.4`)
  - `AD_SERVICE_ACCOUNT_USERNAME`: `CONTOSO\svc-functionapp`
  - `REQUIRED_ROLE`: `Role.PasswordReset`
- [ ] Go to **Settings → Identity**
- [ ] Verify **System Assigned** managed identity is **On**
- [ ] Copy the **Object (principal) ID** for Key Vault access

## Step 7: Store Service Account Credentials ✓

```powershell
# Connect to Azure
Connect-AzAccount

# Grant Key Vault access to managed identity (if not already done)
$functionAppIdentity = (Get-AzFunctionApp -ResourceGroupName 'rg-pwdreset-dev' -Name 'func-pwdreset-dev').IdentityPrincipalId
Set-AzKeyVaultAccessPolicy `
    -VaultName 'kv-pwdreset-dev' `
    -ObjectId $functionAppIdentity `
    -PermissionsToSecrets Get,List

# Store service account password
$serviceAccountPassword = ConvertTo-SecureString 'YourSvcP@ssw0rd!' -AsPlainText -Force
Set-AzKeyVaultSecret `
    -VaultName 'kv-pwdreset-dev' `
    -Name 'ad-service-account-password' `
    -SecretValue $serviceAccountPassword
```

## Step 8: Enable VNet Integration ✓

If function app is on Consumption plan, upgrade to Premium or use Regional VNet Integration:

```powershell
# VNet integration (requires Premium plan or Regional VNet Integration support)
$vnet = Get-AzVirtualNetwork -ResourceGroupName 'rg-pwdreset-dev' -Name 'vnet-pwdreset-dev'
$subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name 'FunctionAppSubnet'

# Update function app with VNet integration
# Note: This may require Premium plan for full support
$functionApp = Get-AzFunctionApp -ResourceGroupName 'rg-pwdreset-dev' -Name 'func-pwdreset-dev'
# Manual configuration in Portal: Settings → Networking → VNet Integration → Add VNet
```

**Alternative for Consumption Plan**: Use Hybrid Connection or configure DNS to resolve domain controller from function app.

## Step 9: Deploy Function Code ✓

```powershell
# Install dependencies
./scripts/Install-Dependencies.ps1

# Package and deploy
Compress-Archive -Path ResetUserPassword, Modules, requirements.psd1, host.json, profile.ps1 -DestinationPath deploy.zip -Force

az functionapp deployment source config-zip `
    --resource-group 'rg-pwdreset-dev' `
    --name 'func-pwdreset-dev' `
    --src deploy.zip
```

## Step 10: Test the Function ✓

### Test Authentication

```powershell
# Get JWT token from your app registration
$token = "YOUR_JWT_TOKEN_HERE"

# Test without authentication (should fail with 401)
Invoke-RestMethod -Uri 'https://func-pwdreset-dev.azurewebsites.net/api/ResetUserPassword' -Method Post

# Test with authentication
$headers = @{ Authorization = "Bearer $token" }
$body = @{ samAccountName = 'testuser1' } | ConvertTo-Json

Invoke-RestMethod `
    -Uri 'https://func-pwdreset-dev.azurewebsites.net/api/ResetUserPassword' `
    -Method Post `
    -Headers $headers `
    -Body $body `
    -ContentType 'application/json'
```

### Expected Response

```json
{
  "message": "Password reset successfully for user testuser1",
  "newPassword": "<generated-password>",
  "samAccountName": "testuser1"
}
```

## Step 11: Run Tests ✓

```powershell
# Run unit tests
Invoke-Pester -Path tests/Unit -Output Detailed -CodeCoverage Modules/**/*.psm1

# Run integration tests (with mocked AD cmdlets)
Invoke-Pester -Path tests/Integration -Output Detailed
```

**Expected Results**:

- 40 tests passing
- > 90% code coverage

## Step 12: Monitor and Validate ✓

- [ ] Check Application Insights for telemetry
- [ ] Verify password reset operations appear in logs
- [ ] Check function app logs for errors
- [ ] Validate security headers in responses

**View Logs**:

```powershell
# Via Portal: Function App → Functions → ResetUserPassword → Monitor → Logs

# Via Application Insights (Kudu):
az monitor app-insights query `
    --app 'appi-pwdreset-dev' `
    --analytics-query 'traces | where timestamp > ago(1h) | order by timestamp desc'
```

## Troubleshooting Common Issues

### Domain Controller Not Accessible

- Verify VNet integration is configured
- Check NSG rules allow AD DS traffic
- Test DNS resolution: `Resolve-DnsName contoso.local` from function app Kudu console
- Verify DC private IP is `10.0.1.4` or FQDN resolves correctly

### Authentication Fails (401)

- Verify JWT token is valid and not expired
- Check app registration `clientId` matches `aud` claim in token
- Verify `Role.PasswordReset` is in token claims
- Check App Service Authentication configuration in Portal

### Password Reset Fails

- Verify service account credentials in Key Vault are correct
- Check service account has password reset permission (ACL)
- Verify function app managed identity has Key Vault access
- Test AD connectivity with `Test-ADUser` from function app (Kudu PowerShell)

## Cleanup

To remove all resources:

```powershell
# Delete resource group (removes all resources)
Remove-AzResourceGroup -Name 'rg-pwdreset-dev' -Force

# Or set deployDomainController to false and redeploy to remove just DC resources
```

## References

- [Main README](../README.md)
- [Domain Controller Setup Guide](DOMAIN-CONTROLLER-SETUP.md)
- [Azure Functions Documentation](https://learn.microsoft.com/azure/azure-functions/)
- [App Service Authentication](https://learn.microsoft.com/azure/app-service/overview-authentication-authorization)
