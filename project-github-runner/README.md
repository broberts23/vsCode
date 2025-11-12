# project-github-runner

Opinionated scaffold to deploy a self-hosted GitHub Actions runner inside a container on Azure (Azure Linux / Azure Linux Container host scenarios).

This project contains:

- `infra/main.bicep` - Bicep template to deploy an Azure Container Instance (container group) running the runner container. The container group is created with a system-assigned managed identity which the deployment will configure for GitHub OIDC.
- `scripts/Deploy-GitHubRunner.ps1` - PowerShell 7.4 script that:
  - creates or ensures the resource group
  - creates a GitHub registration token (if a PAT is provided or retrieved from a secret store)
  - deploys the Bicep template (enables managed identity for the container group)
  - adds a federated identity credential for the container group's managed identity so GitHub OIDC tokens for the repo are trusted
- `scripts/Create-FederatedCredential.ps1` - helper to create a federated identity credential on an application (or service principal) using Microsoft Graph PowerShell (Beta)
- `scripts/ContainerInit.ps1` - helper script intended to run inside the container to install required PowerShell modules (Az, Microsoft.Graph.Beta, SecretManagement)
- `infra/parameters.sample.json` - example parameters for Bicep deploy

Read the scripts' help for how to use them. The design intent is to let you supply the GitHub repo and the script will:

- create a small container group that runs the specified runner container image and enable a system-assigned managed identity
- register the runner using a GitHub registration token (script can request one using a PAT stored in a secret store)
- add a federated identity credential to the managed identity so GitHub OIDC tokens for the repo are trusted by that identity

Security notes
- This scaffold deliberately keeps secrets out of checked-in files. Prefer storing the GitHub PAT in a secret provider:
  - Microsoft.PowerShell.SecretManagement (local/CI): https://learn.microsoft.com/powershell/utility-modules/secretmanagement/overview
  - Azure Key Vault (cloud): https://learn.microsoft.com/azure/key-vault/general/overview

- Example: store PAT in SecretManagement under the name `GitHub.PAT` and run the deploy script with `-UseSecretManagement`.

- The federated identity credential operation touches Microsoft Graph and uses the Microsoft.Graph.Beta module; the beta API is preview and may change. See the script comments for links.

Quick links
- Connect-AzAccount: https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest
- New-AzResourceGroupDeployment: https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest
- Microsoft Graph PowerShell overview (beta): https://learn.microsoft.com/powershell/microsoftgraph/overview?view=graph-powershell-beta

How to store a GitHub PAT (recommended)

1) SecretManagement (local developer / CI):

   - Install: `Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser`
   - Register a vault (example uses SecretStore):

     Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser
     Register-SecretVault -Name SecretStore -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

   - Save the PAT:

     Set-Secret -Name 'GitHub.PAT' -Secret (ConvertTo-SecureString '<your-pat>' -AsPlainText -Force)

   - Run the deploy script with `-UseSecretManagement`.

2) Azure Key Vault (cloud):

   - Create a Key Vault and add the secret using Az or the portal.
   - Provide the vault name to the deploy script via `-SecretVaultName <vault-name>` and the script will attempt to retrieve the secret `GitHub.PAT`.

Container init
- The file `scripts/ContainerInit.ps1` is included for convenience; it installs modules inside the container so the runner can use Az/Graph calls if necessary. You can wire it into your container image or run it as part of the container start command.

See `scripts/Deploy-GitHubRunner.ps1 -?` for usage.
# project-github-runner

Opinionated scaffold to deploy a self-hosted GitHub Actions runner inside a container on Azure (Azure Linux / Azure Linux Container host scenarios).

This project contains:

- `infra/main.bicep` - Bicep template to deploy an Azure Container Instance (container group) running the runner container.
- `scripts/Deploy-GitHubRunner.ps1` - PowerShell 7.4 script that:
  - creates or ensures the resource group
  - creates a GitHub registration token (if a PAT is provided)
  - deploys the Bicep template
  - creates a federated identity credential on an existing Entra application (service principal) to allow GitHub OIDC for the provided repo
- `scripts/Create-FederatedCredential.ps1` - helper to create a federated identity credential on an application using Microsoft Graph PowerShell (Beta)
- `infra/parameters.sample.json` - example parameters for Bicep deploy

Read the scripts' help for how to use them. The design intent is to let you supply the GitHub repo and an Entra application (appId/objectId) and the tooling will:

- create a small container group that runs the specified runner container image
- register the runner using a GitHub registration token (script can request one using a PAT)
- add a federated identity credential to the Entra application so GitHub OIDC tokens for the repo are trusted by that app

Security notes
- This scaffold deliberately keeps secrets out of checked-in files. Supply the GitHub PAT and any registration token at runtime or via secure secrets (Azure Key Vault / SecretManagement). Do not commit PATs.
- The federated identity credential operation touches Microsoft Graph and uses the Microsoft.Graph.Beta module; the beta API is preview and may change. See the script comments for links.

Quick links
- Connect-AzAccount: https://learn.microsoft.com/powershell/module/az.accounts/connect-azaccount?view=azps-latest
- New-AzResourceGroupDeployment: https://learn.microsoft.com/powershell/module/az.resources/new-azresourcegroupdeployment?view=azps-latest
- Microsoft Graph PowerShell overview (beta): https://learn.microsoft.com/powershell/microsoftgraph/overview?view=graph-powershell-beta

See `scripts/Deploy-GitHubRunner.ps1 -?` for usage.
