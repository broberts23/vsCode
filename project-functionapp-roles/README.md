# Password Reset Function App

A secure, high-performance Azure Function App that enables password resets for on-premises Active Directory Domain Services (ADDS) users. The function validates JWT tokens with role-based access control and can handle tens of requests per second.

## 🏗️ Architecture

```mermaid
flowchart LR
    A["Client App<br>with JWT"] -- HTTPS<br>JWT Bearer Token --> B["Function App<br>PowerShell 7.4<br>VNet Integrated"]
    B -- "1.Validate JWT" --> C["Entra ID"]
    B -- "2.Retrieve AD Credentials" --> D["Key Vault<br>AD Service Account"]
    B -- "3.LDAP<br>Password Reset" --> E["Active Directory<br>On-Premises<br>Domain Services"]

    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#BBDEFB
    style D fill:#f3e5f5
    style E fill:#C8E6C9
```

### Components

- **Azure Function App**: PowerShell 7.4 HTTP trigger on Linux Consumption plan with VNet Integration
- **Active Directory**: On-premises ADDS for user password resets
- **AD Service Account**: Domain account with delegated password reset permissions, credentials stored in Key Vault
- **Managed Identity**: Reads AD service account credentials from Key Vault
- **Key Vault**: Secure storage for AD service account credentials (secret: ENTRA-PWDRESET-RW)
- **Application Insights**: Monitoring, logging, and telemetry
- **Entra ID App Registration**: JWT token issuer with `Role.PasswordReset` app role

## 🚀 Features

- ✅ **JWT Bearer Token Authentication**: Validates tokens with signature, expiration, issuer, and audience checks
- ✅ **Role-Based Access Control**: Requires `Role.PasswordReset` claim in JWT token
- ✅ **Secure Password Generation**: Creates complex passwords meeting Azure AD requirements (12-256 chars)
- ✅ **High Performance**: Configured for concurrency with 10 runspaces per worker, 2 workers
- ✅ **Comprehensive Testing**: >80% test coverage with Pester unit and integration tests
- ✅ **Infrastructure as Code**: Complete Bicep templates for repeatable deployments
- ✅ **Security Headers**: HSTS, X-Content-Type-Options, Cache-Control
- ✅ **Structured Logging**: Application Insights integration with sampling

## 📋 Prerequisites

- **Azure Subscription** with permissions to create resources
- **PowerShell 7.4+**: [Download](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
- **Azure PowerShell Modules**:
  ```powershell
  Install-Module -Name Az -Scope CurrentUser -Repository PSGallery -Force
  Install-Module -Name Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force
  Install-Module -Name Pester -Scope CurrentUser -Repository PSGallery -Force -SkipPublisherCheck
  ```
- **Azure Functions Core Tools**: [Download](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- **Bicep CLI**: [Install](https://learn.microsoft.com/azure/azure-resource-manager/bicep/install)
- **Permissions**:
  - Contributor on Azure subscription or resource group
  - Application Administrator or Global Administrator in Entra ID

## 🛠️ Setup Instructions

### Step 1: Clone and Navigate

```powershell
cd /home/ben/vsCode/project-functionapp-roles
```

### Step 2: Update Parameter Files

Edit `infra/parameters.dev.json` (or test/prod) with your values:

```json
{
  "parameters": {
    "tenantId": {
      "value": "YOUR_TENANT_ID"
    },
    "expectedAudience": {
      "value": "api://YOUR_APP_ID"
    },
    "adServiceAccountUsername": {
      "value": "CONTOSO\\svc-pwdreset"
    },
    "adServiceAccountPassword": {
      "reference": {
        "keyVault": {
          "id": "/subscriptions/SUB-ID/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/KV-NAME"
        },
        "secretName": "ad-service-account-password"
      }
    },
    "domainController": {
      "value": "dc01.contoso.local"
    }
  }
}
```

### Step 3: Deploy Infrastructure

```powershell
# Connect to Azure
Connect-AzAccount

# Deploy resources
./scripts/Deploy-Infrastructure.ps1 `
    -Environment dev `
    -ResourceGroupName rg-pwdreset-dev `
    -Location eastus
```

**Outputs**:

- Function App name
- Managed Identity Principal ID
- Key Vault URI
- Application Insights connection string

### Step 4: Configure Entra ID App Registration

Create a new app registration:

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes 'Application.ReadWrite.All'

# Create app registration with Role.PasswordReset app role
./scripts/Configure-AppRegistration.ps1 `
    -DisplayName "Password Reset API" `
    -CreateNew
```

**Or** update an existing app registration:

```powershell
./scripts/Configure-AppRegistration.ps1 `
    -AppId 12345678-1234-1234-1234-123456789abc
```

**Outputs**:

- Application ID
- App ID URI (use for `expectedAudience` parameter)

### Step 5: Configure Network Connectivity

**Option 1: VNet Integration (Recommended for Production)**

1. Create or identify a VNet with connectivity to your Domain Controllers
2. Enable VNet Integration on the Function App:
   ```powershell
   az functionapp vnet-integration add `
       --name <FUNCTION_APP_NAME> `
       --resource-group rg-pwdreset-dev `
       --vnet <VNET_NAME> `
       --subnet <SUBNET_NAME>
   ```

**Option 2: Hybrid Connection or ExpressRoute**

Configure according to your organization's network architecture.

**Verify Connectivity**:

```powershell
# Test from Function App Console (portal)
Test-NetConnection -ComputerName dc01.contoso.local -Port 389
```

### Step 6: Deploy Function App Code

```powershell
# Deploy with tests
./scripts/Deploy-FunctionApp.ps1 `
    -FunctionAppName <FUNCTION_APP_NAME_FROM_STEP_3>

# Or deploy without tests using zip
./scripts/Deploy-FunctionApp.ps1 `
    -FunctionAppName <FUNCTION_APP_NAME> `
    -ResourceGroupName rg-pwdreset-dev `
    -ZipDeploy `
    -RunTests $false
```

### Step 7: Assign Role to Users/Applications

In the Azure Portal, assign the `Role.PasswordReset` role to users or service principals:

1. Navigate to **Entra ID** → **App registrations** → Your app
2. Go to **Enterprise applications** → Find your app
3. **Users and groups** → **Add user/group**
4. Select role: **Password Reset Administrator**

## 🔧 Local Development

### Configure Local Settings

Create or update `local.settings.json`:

```json
{
  "IsEncrypted": false,
  "Values": {
    "AzureWebJobsStorage": "UseDevelopmentStorage=true",
    "FUNCTIONS_WORKER_RUNTIME": "powershell",
    "FUNCTIONS_WORKER_RUNTIME_VERSION": "7.4",
    "TENANT_ID": "YOUR_TENANT_ID",
    "EXPECTED_AUDIENCE": "api://YOUR_APP_ID",
    "EXPECTED_ISSUER": "https://sts.windows.net/YOUR_TENANT_ID/",
    "REQUIRED_ROLE": "Role.PasswordReset",
    "KEY_VAULT_URI": "https://your-keyvault.vault.azure.net/",
    "AD_SERVICE_USERNAME": "CONTOSO\\svc-pwdreset",
    "AD_SERVICE_PASSWORD": "YourPasswordHere",
    "DOMAIN_CONTROLLER": "dc01.contoso.local"
  }
}
```

### Run Locally

```powershell
# Install dependencies (first time only)
func extensions install

# Start function
func start
```

The function will be available at: `http://localhost:7071/api/ResetUserPassword`

### Run Tests

```powershell
# Run all tests
Invoke-Pester -Path ./tests

# Run unit tests only
Invoke-Pester -Path ./tests/Unit

# Run with code coverage
Invoke-Pester -Path ./tests -CodeCoverage ./Modules/**/*.psm1,./ResetUserPassword/run.ps1
```

## 📡 API Usage

### Endpoint

```
POST https://<function-app-name>.azurewebsites.net/api/ResetUserPassword
```

### Request Headers

```http
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json
```

### Request Body

```json
{
  "samAccountName": "jdoe",
  "domainController": "dc01.contoso.local"
}
```

Note: `domainController` is optional. If not provided, Active Directory will use DNS to locate a domain controller.

### Success Response (200 OK)

```json
{
  "samAccountName": "jdoe",
  "password": "GeneratedPassword123!",
  "resetTime": "2024-01-15T14:30:00Z",
  "status": "success"
}
```

### Error Responses

| Code | Description                                                                                  |
| ---- | -------------------------------------------------------------------------------------------- |
| 400  | Bad Request - Missing samAccountName or invalid format                                       |
| 401  | Unauthorized - Missing, invalid, or expired JWT token                                        |
| 403  | Forbidden - Missing Role.PasswordReset claim                                                 |
| 404  | Not Found - User does not exist in Active Directory                                          |
| 500  | Internal Server Error - Active Directory error, access denied, or network connectivity issue |

## 🔐 Security Considerations

### JWT Token Validation

The function performs comprehensive JWT validation:

1. **Format Check**: Verifies Bearer token format
2. **Signature Validation**: Uses System.IdentityModel.Tokens.Jwt library
3. **Expiration Check**: Validates `ValidTo` and `ValidFrom` claims
4. **Issuer Validation**: Matches `EXPECTED_ISSUER` environment variable
5. **Audience Validation**: Matches `EXPECTED_AUDIENCE` environment variable
6. **Role Check**: Requires `Role.PasswordReset` in 'roles' or 'role' claim

### Active Directory Service Account

- **Secure Credential Storage**: AD credentials stored in Key Vault, retrieved via Managed Identity
- **Delegated Permissions**: Service account has only password reset delegation on specific OUs
- **Least Privilege**: Cannot modify accounts in Admin OUs or with protected group membership
- **RBAC**: Key Vault Secrets User role for Managed Identity to access AD credentials

### Password Security

- **Complexity**: Minimum 12 characters, includes uppercase, lowercase, digits, special characters
- **Uniqueness**: Cryptographically secure random generation
- **No Logging**: Passwords never written to logs or Application Insights

### Network Security

- **HTTPS Only**: TLS 1.2+ enforced
- **Security Headers**: HSTS, X-Content-Type-Options
- **CORS**: Configure via Azure Portal if needed

## 📊 Monitoring

### Application Insights

View telemetry in the Azure Portal:

```powershell
# Get App Insights connection string
az functionapp config appsettings list `
    --name <function-app-name> `
    --resource-group <resource-group> `
    --query "[?name=='APPLICATIONINSIGHTS_CONNECTION_STRING'].value" -o tsv
```

### Key Metrics

- **Request Rate**: Requests per second
- **Response Time**: P50, P95, P99 latencies
- **Error Rate**: 4xx and 5xx responses
- **Dependencies**: Microsoft Graph API call duration and failures

### Log Queries (KQL)

```kusto
// Recent password reset requests
requests
| where name == "ResetUserPassword"
| where timestamp > ago(1h)
| project timestamp, resultCode, duration, customDimensions.samAccountName

// Failed authentication attempts
traces
| where message contains "JWT validation failed" or message contains "Role check failed"
| where timestamp > ago(1h)
| summarize count() by bin(timestamp, 5m)

// Active Directory errors
traces
| where message contains "Cannot find an object" or message contains "Access is denied"
| where timestamp > ago(1h)
| project timestamp, message, severityLevel
```

## 🧪 Testing

### Test Structure

```
tests/
├── Unit/
│   └── PasswordResetHelpers.Tests.ps1    # Module function tests
└── Integration/
    └── ResetUserPassword.Tests.ps1       # HTTP function tests
```

### Test Coverage

- **Module Load**: Verifies 4 exported functions
- **Test-JwtToken**: 8 test cases (null, empty, invalid format, expiration, issuer, audience)
- **Test-RoleClaim**: 5 test cases (null principal, role exists, doesn't exist, no roles, case sensitivity)
- **New-SecurePassword**: 11 test cases (length validation, complexity requirements, uniqueness)
- **Set-UserPassword**: 8 test cases (parameter validation, Update-MgUser invocation, WhatIf support)
- **HTTP Function**: 10 integration test cases (request validation, JWT validation, role authorization, password operations)

**Total**: 40+ test cases with >80% code coverage

### Running Tests

```powershell
# All tests with coverage report
$config = New-PesterConfiguration
$config.Run.Path = './tests'
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = './Modules/**/*.psm1', './ResetUserPassword/run.ps1'
$config.CodeCoverage.OutputFormat = 'JaCoCo'
$config.CodeCoverage.OutputPath = './coverage.xml'
Invoke-Pester -Configuration $config
```

## 🔍 Troubleshooting

### Common Issues

#### 1. "JWT validation failed"

**Cause**: Token expired, invalid signature, or wrong issuer/audience

**Solution**:

```powershell
# Verify token claims
$token = "YOUR_TOKEN"
$claims = [System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler]::new().ReadJwtToken($token)
$claims.Claims | Format-Table
```

Check:

- `exp` (expiration) is in the future
- `iss` (issuer) matches `EXPECTED_ISSUER`
- `aud` (audience) matches `EXPECTED_AUDIENCE`

#### 2. "Role check failed: Role.PasswordReset not found"

**Cause**: Missing role assignment or incorrect claim name

**Solution**:

- Verify app role is assigned to user/service principal in Entra ID
- Check JWT token contains 'roles' or 'role' claim with 'Role.PasswordReset' value

#### 3. "Access is denied"

**Cause**: AD service account missing password reset permissions

**Solution**:

```powershell
# Verify service account has delegated permissions
# In Active Directory Users and Computers:
# 1. Right-click target OU → Delegate Control
# 2. Add service account
# 3. Grant "Reset user passwords and force password change at next logon"
```

#### 4. "Cannot find an object with identity: 'username'"

**Cause**: User doesn't exist in Active Directory or wrong samAccountName

**Solution**:

```powershell
# Verify user exists in AD
Get-ADUser -Identity "jdoe" -Server dc01.contoso.local
```

#### 5. "Unable to contact the server"

**Cause**: Network connectivity issue between Function App and Domain Controller

**Solution**:

- Verify VNet Integration is configured
- Test connectivity from Function App console (Azure Portal):
  ```powershell
  Test-NetConnection -ComputerName dc01.contoso.local -Port 389
  ```
- Check NSG rules allow LDAP traffic (TCP 389/636)

#### 5. Function app not responding

**Cause**: Cold start, deployment issue, or runtime error

**Solution**:

```powershell
# Check function app logs
func azure functionapp logstream <function-app-name>

# Or view in Application Insights
# Navigate to: Function App → Monitor → Logs
```

### Debug Mode

Enable detailed logging by setting log level in `host.json`:

```json
{
  "logging": {
    "logLevel": {
      "default": "Debug"
    }
  }
}
```

## 📚 Additional Resources

### PowerShell 7.4

- [PowerShell Documentation](https://learn.microsoft.com/powershell/scripting/overview?view=powershell-7.4)
- [About Functions Advanced](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_functions_advanced?view=powershell-7.4)

### Azure Functions

- [PowerShell Developer Guide](https://learn.microsoft.com/azure/azure-functions/functions-reference-powershell)
- [HTTP Trigger Reference](https://learn.microsoft.com/azure/azure-functions/functions-bindings-http-webhook-trigger)
- [Best Practices](https://learn.microsoft.com/azure/azure-functions/functions-best-practices)

### Active Directory

- [Set-ADAccountPassword](https://learn.microsoft.com/powershell/module/activedirectory/set-adaccountpassword)
- [Set-ADUser](https://learn.microsoft.com/powershell/module/activedirectory/set-aduser)
- [Active Directory Module](https://learn.microsoft.com/powershell/module/activedirectory)

### Managed Identities

- [Overview](https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)
- [Using with Azure Functions](https://learn.microsoft.com/azure/app-service/overview-managed-identity)

### Bicep

- [Bicep Documentation](https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview)
- [Best Practices](https://learn.microsoft.com/azure/azure-resource-manager/bicep/best-practices)

## 📄 License

This project is provided as-is for educational and reference purposes.

## 🤝 Contributing

Contributions are welcome! Please ensure:

- All Pester tests pass
- Code follows PowerShell best practices
- New features include comprehensive tests
- Documentation is updated

## 📧 Support

For issues or questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review Application Insights logs
3. Consult Microsoft Learn documentation links provided throughout

---

**Built with PowerShell 7.4 | Azure Functions v4 | Active Directory Domain Services**
