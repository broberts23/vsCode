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

- **Domain joined for Kerberos Authentication**: This enables the VM to leverage native Kerberos authentication for downstream connections. This is a lifesaver for scenarios like on-premises mailbox migrations where security teams rightly block Basic WinRM access to the Exchange servers' `/PowerShell` endpoints. The Azure Function securely connects to the isolated Jumpbox, and the Jumpbox can seamlessly use Kerberos to act against the backend Exchange environment or other domain resources.
- **RSAT (Remote Server Administration Tools)** installed natively.
- **Exchange Management Tools** (or other legacy admin prerequisites) installed locally.
- **WinRM Basic enabled**: Strictly locked down over HTTPS and firewalled to the VNet. This provides a secure, certificate-pinned bridge from the cloud without exposing your actual Domain Controllers or Exchange servers to edge traffic.

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

The script block executes natively on the remote Windows machine, in a context that has the Active Directory and Exchange tooling readily available. The results are serialized back over PowerShell remoting to the function. (For a production service, this free-form script execution should be replaced with a strict allow-list of parameterized, approved operations).

### Seeing It In Action

<!-- [Placeholder: Screenshot of the Azure Portal showing the Function App and Management VM architecture] -->

To call the Azure Function, you send an HTTP POST request with a JSON payload containing the script and any required arguments. Here is an example of retrieving an Active Directory user via the jumpbox:

```powershell
$uri = "https://<your-function-app>.azurewebsites.net/api/InvokeLegacyCommand"
$body = @{
    scriptText = "Get-ADUser -Identity `$args[0] -Properties EmailAddress | Select-Object Name, EmailAddress, UserPrincipalName"
    arguments  = @("jdoe")
} | ConvertTo-Json

Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/json"
```

<!-- [Placeholder: Screenshot of Postman or PowerShell console showing the successful JSON response returning the AD user object] -->

### Explicit TLS Validation and Secure Remoting

The tricky part of WinRM over HTTPS from an Azure Function is certificate trust. Writing lab-issued or self-signed certificates into the shared worker's machine store is messy.

This scaffold handles trust explicitly at the application layer:

1. The function securely loads the expected certificate from Key Vault using native App Settings references.
2. Before creating the PSSession, it opens a raw TLS connection to the management VM (e.g., `managementvm.contoso.local:5986`).
3. It inspects the remote certificate for a thumbprint match and verifies the DNS identity against the configured hostname.
4. Only after this preflight passes does it establish the remoting session.

This approach ensures zero-trust TLS validation without modifying the underlying OS trust store. Furthermore, while Basic Auth is typically discouraged, it is defensible here because it operates strictly over a private VNet on an HTTPS-encrypted channel, with credentials securely retrieved from Key Vault just-in-time.

## Conclusion

Creating a bridge between modern serverless architectures and legacy on-premises tooling doesn't require compromising on security or maintainability. By offloading the heavy lifting of Exchange Management Tools or Active Directory RSAT to a dedicated jumpbox VM, your Azure Functions remain lightweight, secure, and easily updatable.

This pattern allows you to bypass the pitfalls of direct LDAP while preserving the usability of native PowerShell cmdlets. To take this scaffold even further for production, consider replacing the flexible script evaluation with JEA (Just Enough Administration) endpoints, adding a secondary VM for high availability, and implementing automated certificate rotation.
