# Using A Domain-Joined Jumpbox VM For Legacy PowerShell From Azure Functions

## Introduction and Use Cases

Some automation problems are not really Azure Functions problems. They are dependency-bound Windows administration problems.

As organizations move their identity and access lifecycle to the cloud, building automation around legacy on-premises services becomes a challenge. A common scenario is automating mailbox creation or adjusting Active Directory attributes. While direct LDAP from an Azure Function via VNet integration is possible, it often falls short in complex environments. Direct LDAP forces you to manage raw directory schema changes, lacks the safety nets built into native cmdlets, and offers no support for specialized tools like the Exchange Management Tools.

Exchange, for instance, requires full PowerShell snap-ins or modules that are tightly coupled to a traditional Windows Server environment. Similarly, some organizations prefer not to expose their Domain Controllers directly to application subnets via LDAP, preferring instead a controlled, auditable jumpbox that intermediates these privileged actions.

By using a domain-joined management VM as a jumpbox, organizations can execute legacy commands—such as Active Directory cmdlets and Exchange administrative tasks—securely from a modern Serverless frontend, without compromising the integrity of the network or struggling with direct LDAP complexities.

## The Architecture: Function App Meets Management VM

The cleaner boundary is to let the Azure Function handle authentication, authorization, and request validation, and then hand off execution to a domain-joined management VM built specifically for these legacy dependencies.

The function app stays lean and modern:

- **PowerShell 7.4 runtime**
- **Easy Auth for zero-code token validation**: Rather than writing custom JWT parsing logic in your script, Azure App Service Authentication is wired directly to an Entra ID App Registration. It automatically intercepts unauthenticated traffic and returns a `401 Unauthorized` at the edge before the PowerShell function is even initialized. This ensures only trusted, authenticated identities can attempt to trigger highly privileged AD or Exchange commands.
- **Key Vault integration via managed identity** (using native App Service References)
- **VNet-integrated networking** to safely reach the internal VM

The management VM carries the legacy burden:

- **Domain joined for downstream domain access**: The management VM can use native domain-integrated authentication for downstream connections in ways that a Function App worker cannot. That matters for scenarios like on-premises mailbox migrations where security teams rightly block Basic WinRM access to the Exchange servers' `/PowerShell` endpoints. The important nuance is that the Azure Function is not domain joined, so the first hop to the jumpbox is not Kerberos from the function host. It is WinRM over HTTPS using `Negotiate` with explicit credentials, which typically means NTLM on that first hop. Downstream access from the jumpbox still needs to account for the classic second-hop problem.
- **RSAT (Remote Server Administration Tools)** installed natively.
- **Exchange Management Tools** (or other legacy admin prerequisites) installed locally.
- **WinRM over HTTPS with explicit credentials**: The function establishes a certificate-pinned HTTPS remoting session to the jumpbox and authenticates with explicit credentials using Negotiate. This provides a secure bridge from the cloud without exposing your actual Domain Controllers or Exchange servers to edge traffic.

### Executing the Remote Script Block

The function receives a request payload containing script text and optional arguments. Inside the function, that payload is passed via `Invoke-Command -AsJob` to the management VM.

```powershell
$invokeParameters = @{
  Session = $session
  AsJob = $true
  ScriptBlock = {
    param($scriptText, $scriptArguments)

    & ([scriptblock]::Create($scriptText)) @scriptArguments
  }
  ArgumentList = @($incomingScriptText, $incomingArguments)
}

$job = Invoke-Command @invokeParameters
$result = Receive-Job -Job $job -Wait -AutoRemoveJob
```

The script block executes natively on the remote Windows machine, in a context that has the Active Directory and Exchange tooling readily available. The results are serialized back over PowerShell remoting to the function. One important operational detail is that this does not magically eliminate second-hop constraints. If the remote script needs to talk onward to a domain controller or Exchange endpoint, you may still need explicit downstream credentials, a RunAs endpoint, or a JEA design. (For a production service, this free-form script execution should be replaced with a strict allow-list of parameterized, approved operations).

### Seeing It In Action

<!-- [Placeholder: Screenshot of the Azure Portal showing the Function App and Management VM architecture] -->

To call the Azure Function, you send an HTTP POST request with a JSON payload containing the script and any required arguments. Here is an example of retrieving an Active Directory user via the jumpbox:

```powershell
$tenantId = '<tenant-id>'
$clientId = '<caller-app-client-id>'
$clientSecret = '<caller-app-client-secret>'
$scope = 'api://<api-app-registration-client-id>/.default'
$functionAppName = '<your-function-app-name>'

$tokenResponse = Invoke-RestMethod `
  -Method Post `
  -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
  -ContentType 'application/x-www-form-urlencoded' `
  -Body @{
    client_id = $clientId
    client_secret = $clientSecret
    grant_type = 'client_credentials'
    scope = $scope
  }

$body = @{
    scriptBlock = 'Get-ADUser -Server $Server -Credential $LegacyCredential -Identity $SamAccountName -Properties EmailAddress | Select-Object Name, EmailAddress, UserPrincipalName'
    arguments = @{
        SamAccountName = 'jdoe'
        Server = 'legacyjump-dc-d.contoso.local'
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
    -Uri "https://$functionAppName.azurewebsites.net/api/InvokeLegacyCommand" `
    -Method Post `
  -Headers @{ Authorization = "Bearer $($tokenResponse.access_token)" } `
    -Body $body `
    -ContentType 'application/json'
```

<!-- [Placeholder: Screenshot of Postman or PowerShell console showing the successful JSON response returning the AD user object] -->

### Explicit TLS Validation and Secure Remoting

The tricky part of WinRM over HTTPS from an Azure Function is certificate trust. Writing lab-issued or self-signed certificates into the shared worker's machine store is messy.

This scaffold handles trust explicitly at the application layer:

1. The function securely loads the expected certificate from Key Vault using native App Settings references.
2. Before creating the PSSession, it opens a raw TLS connection to the management VM (e.g., `managementvm.contoso.local:5986`).
3. It inspects the remote certificate for a thumbprint match and verifies the DNS identity against the configured hostname.
4. Only after this preflight passes does it establish the remoting session.

This approach ensures zero-trust TLS validation without modifying the underlying OS trust store. The remoting session then uses `Negotiate` over that HTTPS channel with credentials retrieved from Key Vault just-in-time. In practice, because the Function App is not domain joined, that first hop should be understood as `Negotiate` with explicit credentials, typically using NTLM rather than Kerberos. If the remote script must authenticate onward to Active Directory or Exchange, the script can use the injected `$LegacyCredential` variable or move to a RunAs or JEA endpoint model in more complex environments.

## Conclusion

Creating a bridge between modern serverless architectures and legacy on-premises tooling doesn't require compromising on security or maintainability. By offloading the heavy lifting of Exchange Management Tools or Active Directory RSAT to a dedicated jumpbox VM, your Azure Functions remain lightweight, secure, and easily updatable.

This pattern allows you to bypass the pitfalls of direct LDAP while preserving the usability of native PowerShell cmdlets. To take this scaffold even further for production, consider replacing the flexible script evaluation with JEA (Just Enough Administration) endpoints, adding a secondary VM for high availability, and implementing automated certificate rotation.

If you want to see a working example of this pattern, check out the full code in my GitHub repo, where I've built out this architecture with sample scripts and detailed documentation.

## Links and References

- [Azure Functions documentation](https://learn.microsoft.com/azure/azure-functions/)
- [Azure App Service Authentication and Authorization](https://learn.microsoft.com/azure/app-service/overview-authentication-authorization)
- [about_Remote_Troubleshooting](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_troubleshooting)
- [WinRM security considerations](https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management)
- [Just Enough Administration (JEA)](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/overview)
- [My GitHub repo](https://github.com/broberts23/vsCode/tree/main/project-functionapp-jumpbox#legacy-powershell-jumpbox-function-app)
