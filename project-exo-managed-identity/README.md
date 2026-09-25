# Exchange Online managed-identity connection gate

PowerShell 7.6 Azure Function App that opens an Exchange Online managed-identity session in `profile.ps1` and validates or refreshes it through a process-wide `SemaphoreSlim` before a basic read (`Get-AcceptedDomain`).

## Prerequisites

- Azure subscription with rights to deploy Function Apps on **Windows Elastic Premium (EP1)**
- PowerShell 7.4+ locally for deployment scripts (`Az` modules)
- Azure CLI (`az`) logged in, for Graph app-role assignment
- An existing Exchange Online PowerShell session as an Exchange admin, for RBAC-for-Applications assignment
- Tenant `*.onmicrosoft.com` domain for `EXCHANGE_ORGANIZATION`

PowerShell 7.6 on Azure Functions is preview and Windows-only. ExchangeOnlineManagement 3.10.0+ requires that runtime.

## Deploy order

1. **Infrastructure** — create the resource group and Function App:

   ```powershell
   ./scripts/Deploy-Infrastructure.ps1 -Environment dev -ResourceGroupName rg-exomi-dev
   ```

2. **Exchange permissions** — grant `Exchange.ManageAsApp` and `View-Only Configuration` to the managed identity (operator must already be connected to Exchange Online):

   ```powershell
   Connect-ExchangeOnline -Organization contoso.onmicrosoft.com
   ./scripts/Grant-ExchangeOnlinePermissions.ps1 `
     -SubscriptionId <sub-id> `
     -ResourceGroupName rg-exomi-dev `
     -FunctionAppName <function-app-name>
   ```

3. **Function code** — zip-deploy `FunctionApp/`:

   ```powershell
   ./scripts/Deploy-FunctionApp.ps1 `
     -ResourceGroupName rg-exomi-dev `
     -FunctionAppName <function-app-name>
   ```

4. **Smoke test** — call `GET /api/TestExchangeConnection` with a function key and confirm accepted domains in the JSON body.

## Operator permissions

| Step | Who | Rights |
|------|-----|--------|
| Deploy-Infrastructure | Azure contributor on the target resource group | Create EP1 plan, Function App, storage, monitoring |
| Grant-ExchangeOnlinePermissions | Entra + Exchange admin | Assign `Exchange.ManageAsApp`; create Exchange service principal and `View-Only Configuration` role assignment |
| Deploy-FunctionApp | Azure contributor on the Function App | Zip publish |

## Project layout

```text
project-exo-managed-identity/
├── FunctionApp/
│   ├── Modules/ExchangeOnlineConnection/   # SemaphoreSlim gate + refresh
│   ├── TestExchangeConnection/             # HTTP smoke test
│   ├── profile.ps1                         # Initial Connect-ExchangeOnline
│   ├── host.json
│   └── requirements.psd1
├── infra/                                  # Bicep
├── scripts/                                # Deploy + grant
├── tests/Unit/                             # Pester
└── blog.md
```

See [blog.md](blog.md) for the design narrative and screenshot placeholders.
