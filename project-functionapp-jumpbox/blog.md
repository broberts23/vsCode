# Using A Domain-Joined Jumpbox VM For Legacy PowerShell From Azure Functions

Some automation problems are not really Azure Functions problems. They are dependency-bound Windows administration problems.

If the command you need depends on the `ActiveDirectory` module, Exchange remoting, RSAT, or a domain-joined Windows machine, pushing that directly into an Azure Function usually creates a brittle design. The cleaner boundary is to let the function authenticate, authorize, validate the request, and then hand off execution to a domain-joined management VM that is built for those legacy dependencies.

## The Pattern

The function app stays lean:

- PowerShell 7.4
- Easy Auth for token validation
- Key Vault via managed identity
- VNet-integrated networking

The management VM carries the legacy burden:

- domain joined
- RSAT installed
- Exchange or other legacy admin tools installed
- WinRM Basic enabled only over HTTPS

That split matters because it keeps the function host modern and disposable while still giving you a controlled place to run older commands.

## How The Remote Script Block Runs

The function receives a request body that includes script text and optional arguments. Inside the function, that payload is passed to `Invoke-Command -AsJob` against the management VM.

Conceptually, the flow looks like this:

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

The important point is where the script block is created and executed: on the remote machine. That means the code runs in the context that actually has the AD or Exchange tooling available. The output is serialized back over PowerShell remoting and returned by the function.

For a blog demo, free-form script text makes the execution boundary easy to show. For a production service, replace that with an allow list of approved operations.

## How HTTPS Validation Works

The awkward part of WinRM over HTTPS in a function app is certificate trust. You often do not want to write certificates into the worker's machine store, and you may be using a self-signed or lab-issued certificate anyway.

This scaffold handles that explicitly:

1. The function loads the expected certificate from Key Vault.
2. Before creating the PSSession, it opens a TLS connection to `managementvm.contoso.local:5986`.
3. It inspects the remote certificate.
4. It checks that the thumbprint matches the pinned certificate from Key Vault.
5. It checks that the certificate identity matches the configured hostname.

Only after that preflight passes does the function create the remoting session.

That is why the blog can honestly say TLS validation still happens. The trust decision is just explicit and application-managed instead of delegated to the operating system trust store.

## Why Basic Auth Is Still Defensible Here

Normally, Basic authentication is the wrong direction. In this narrow case it can be acceptable because:

- it is used only on a private network path
- it is bound to HTTPS only
- the credential is stored in Key Vault
- the function authenticates callers before remoting begins

The point is not that Basic is modern. The point is that it remains compatible with older remoting patterns while the TLS layer protects the credential on the wire.

## Where To Take The Scaffold Next

- Replace free-form script blocks with named operations.
- Add a second management VM and pick from a pool for resilience.
- Add JEA endpoints instead of broad remoting rights.
- Publish the jumpbox certificate or issuing CA through a stricter rotation workflow.
- Add integration tests that validate the TLS preflight and remoting handshake.
