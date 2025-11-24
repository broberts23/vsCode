# Quick Start Guide

Get the Password Reset Function App for on-premises Active Directory running in under 15 minutes.

**Note**: This guide assumes you already have:

- An Active Directory domain with network connectivity from Azure
- A service account with delegated password reset permissions
- The service account password stored in a temporary Key Vault

## Prerequisites Check

```powershell
# Verify PowerShell version (need 7.4+)
$PSVersionTable.PSVersion

# Check Azure CLI/PowerShell
Get-Command az -ErrorAction SilentlyContinue
Get-Command Connect-AzAccount -ErrorAction SilentlyContinue

# Check Bicep
bicep --version

# Check Functions Core Tools
func --version
```

## Rapid Deployment

### 1. Install Dependencies (if needed)

```powershell
# Azure PowerShell
Install-Module -Name Az -Scope CurrentUser -Force

# Active Directory (if testing locally on Windows with RSAT)
Install-Module -Name ActiveDirectory -Scope CurrentUser -Force -SkipPublisherCheck

# Pester
Install-Module -Name Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

### 2. Connect to Azure

```powershell
Connect-AzAccount
```

### 3. Get Your Tenant ID

```powershell
$tenantId = (Get-AzContext).Tenant.Id
Write-Host "Tenant ID: $tenantId"
```

### 4. Create App Registration

```powershell
./scripts/Configure-AppRegistration.ps1 -DisplayName "Password Reset API" -CreateNew
```

**Save the output**: You'll need the Application ID (AppId) and App ID URI.

### 5. Update Parameters

Edit `infra/parameters.dev.json`:

```powershell
# Open in VS Code
code infra/parameters.dev.json
```

Replace:

- `YOUR_TENANT_ID_HERE` → Your tenant ID from step 3
- `YOUR_APP_ID_HERE` → The App ID URI from step 4 (e.g., `api://password-reset-12345...`)
- `CONTOSO\\svc-pwdreset` → Your AD service account username
- Key Vault reference → Path to your temporary Key Vault with the AD password
- `dc01.contoso.local` → Your domain controller FQDN

### 6. Deploy Infrastructure

```powershell
./scripts/Deploy-Infrastructure.ps1 `
    -Environment dev `
    -ResourceGroupName rg-pwdreset-dev `
    -Location eastus
```

**Save these outputs**:

- `functionAppName`
- `functionAppPrincipalId`

### 7. Configure Network Connectivity

**Set up VNet Integration:**

```powershell
# If you don't have a VNet with connectivity to your Domain Controllers:
# 1. Create VNet with site-to-site VPN or ExpressRoute to on-premises
# 2. Create a subnet for Function App integration

# Enable VNet Integration
az functionapp vnet-integration add `
    --name <FUNCTION_APP_NAME_FROM_STEP_6> `
    --resource-group rg-pwdreset-dev `
    --vnet <YOUR_VNET_NAME> `
    --subnet <YOUR_SUBNET_NAME>
```

**Verify connectivity:**

```powershell
# From Azure Portal:
# Function App → Console → Run:
Test-NetConnection -ComputerName dc01.contoso.local -Port 389
```

### 8. Deploy Function Code

```powershell
./scripts/Deploy-FunctionApp.ps1 -FunctionAppName <FUNCTION_APP_NAME_FROM_STEP_6>
```

**Important**: The Function App must be able to reach your Domain Controllers via LDAP (port 389/636) for password resets to work.

### 9. Test the Function

#### Get a Test Token

First, create a client secret for your app registration:

```powershell
# In Azure Portal:
# 1. Go to App registrations → Your app
# 2. Certificates & secrets → New client secret
# 3. Copy the secret value
```

Request a token:

```powershell
$tenantId = "YOUR_TENANT_ID"
$clientId = "YOUR_APP_CLIENT_ID"  # The AppId (not the URI)
$clientSecret = "YOUR_CLIENT_SECRET"
$scope = "api://YOUR_APP_ID/.default"  # The App ID URI + /.default

$body = @{
    client_id     = $clientId
    scope         = $scope
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

$tokenResponse = Invoke-RestMethod `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Method Post `
    -Body $body

$token = $tokenResponse.access_token
Write-Host "Token obtained: $($token.Substring(0,50))..."
```

#### Assign the Role

Before testing, assign the role to your service principal:

1. Go to **Entra ID** → **Enterprise applications**
2. Search for your app name ("Password Reset API")
3. Click **Users and groups** → **Add user/group**
4. Select **Password Reset Administrator** role
5. Click **Assign**

#### Call the Function

```powershell
$functionUrl = "https://<FUNCTION_APP_NAME>.azurewebsites.net/api/ResetUserPassword"
$testSamAccountName = "jdoe"  # Replace with real test user's samAccountName

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$body = @{
    samAccountName = $testSamAccountName
    domainController = "dc01.contoso.local"  # Optional
} | ConvertTo-Json

$response = Invoke-RestMethod `
    -Uri $functionUrl `
    -Method Post `
    -Headers $headers `
    -Body $body

Write-Host "Success! New password: $($response.password)"
```

## What You Created

✅ **Function App**: PowerShell 7.4 on Linux Consumption plan  
✅ **Storage Account**: For function state and triggers  
✅ **Key Vault**: For secure secret storage  
✅ **Application Insights**: For monitoring and logs  
✅ **Managed Identity**: With Key Vault Secrets User role  
✅ **AD Service Account Secret**: Stored in Key Vault (ENTRA-PWDRESET-RW)  
✅ **VNet Integration**: For connectivity to Domain Controllers  
✅ **App Registration**: With Role.PasswordReset app role

## Next Steps

### Add More Authorized Users/Apps

```powershell
# For a user
# Portal: Entra ID → Enterprise apps → Your app → Users and groups → Add user

# For another service principal (app)
# Portal: Entra ID → Enterprise apps → Your app → Users and groups → Add user → Select applications
```

### Monitor Usage

```powershell
# View logs
func azure functionapp logstream <FUNCTION_APP_NAME>

# Or in portal: Function App → Monitor → Logs
```

### Update Configuration

```powershell
# Update app settings
az functionapp config appsettings set `
    --name <FUNCTION_APP_NAME> `
    --resource-group rg-pwdreset-dev `
    --settings "REQUIRED_ROLE=CustomRole.Name"
```

### Deploy to Test/Prod

```powershell
# Update parameters.test.json or parameters.prod.json
# Then deploy:
./scripts/Deploy-Infrastructure.ps1 `
    -Environment test `
    -ResourceGroupName rg-pwdreset-test `
    -Location eastus

./scripts/Deploy-FunctionApp.ps1 `
    -FunctionAppName <NEW_FUNCTION_APP_NAME>
```

## Troubleshooting Quick Fixes

### "JWT validation failed"

Check token expiration and claims:

```powershell
# Decode JWT
$jwtHandler = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new()
$token = "YOUR_TOKEN_HERE"
$jwt = $jwtHandler.ReadJwtToken($token)
$jwt.Claims | Format-Table Type, Value
```

### "Role check failed"

Verify role assignment:

```powershell
# In portal: Entra ID → Enterprise apps → Your app → Users and groups
# Ensure "Password Reset Administrator" role is assigned
```

### "Cannot find an object with identity"

Verify user exists in Active Directory:

```powershell
Get-ADUser -Identity "jdoe" -Server dc01.contoso.local
```

### "Access is denied"

Verify service account has delegated permissions:

```powershell
# In Active Directory Users and Computers:
# 1. Right-click target OU → Delegate Control
# 2. Add service account (svc-pwdreset)
# 3. Grant "Reset user passwords and force password change at next logon"
```

### "Unable to contact the server"

Check network connectivity:

```powershell
# From Function App Console in Azure Portal
Test-NetConnection -ComputerName dc01.contoso.local -Port 389
```

### Function not responding

Restart the function app:

```powershell
az functionapp restart --name <FUNCTION_APP_NAME> --resource-group rg-pwdreset-dev
```

## Clean Up

Remove all resources when done testing:

```powershell
# WARNING: This deletes everything!
Remove-AzResourceGroup -Name rg-pwdreset-dev -Force
```

## Learn More

- Full README: [README.md](./README.md)
- Test the function: Run Pester tests with `Invoke-Pester -Path ./tests`
- View metrics: Portal → Function App → Monitor → Metrics

---

**Total deployment time: ~15 minutes** ⚡  
**Note**: Excludes network setup time (VPN/ExpressRoute configuration)
