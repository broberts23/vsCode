# Keeping Exchange Online Alive Behind a SemaphoreSlim Gate

Cold starts are expensive when the work you’re trying to do is `Connect-ExchangeOnline`. On a PowerShell Function App the managed-identity handshake is honest but slow, and the Exchange Online Management module is not shy about memory. If every HTTP request rebuilds the session from scratch, you pay for the connect on every invocation and you invite the kind of session thrash that shows up as timeouts under concurrency. The pattern in this sample is deliberately boring: open the session once when the runspace starts, keep it around, and put a process-wide gate in front of anything that might recreate it.

PowerShell 7.6 is what makes the story current. Azure Functions supports 7.6 as a Windows-only preview runtime on .NET 10, and ExchangeOnlineManagement 3.10.0 and later lean on that same .NET 10 surface. That combination forces a Windows Elastic Premium plan, a warm minimum instance count, and an app setting that names the worker version explicitly. Consumption would recycle the process and throw the carefully warmed session away the moment traffic went quiet.

## Why the session lives in profile.ps1

Azure Functions runs `profile.ps1` once per PowerShell runspace on cold start. That is the right place for identity-bound setup that should already be true before your first function body runs. In this project the profile does almost nothing on its own. It imports the helper module and asks for an initial managed-identity connection.

```powershell
Import-Module ExchangeOnlineConnection -Force
Initialize-ExchangeOnlineConnection
```

`Initialize-ExchangeOnlineConnection` still goes through the same gate the HTTP path uses. The profile is the place the session is born; the module is the place that decides whether birth is still needed. On a warm worker the second runspace created for in-proc concurrency can look at `Get-ConnectionInformation`, see an `Active` token, and skip the connect. On a brand-new worker it takes the lock, calls `Connect-ExchangeOnline -ManagedIdentity`, and leaves a session ready for the first request.

![Function App configuration showing PowerShell 7.6](images/01-powershell-76-configuration.png)

*Capture: Function App → Configuration → General settings, with PowerShell version set to 7.6 and the FUNCTIONS\_WORKER\_RUNTIME\_VERSION app setting visible.*

## Why refresh lives in the module

Tokens expire. Workers get recycled. A connection that looked fine at profile time can be dead by the time a timer or HTTP trigger needs it. Putting the health check next to the connect keeps every caller honest without making them reimplement Exchange Online’s connection model.

`Assert-ExchangeOnlineConnection` waits on the gate, asks `Get-ConnectionInformation` for an `Active` `TokenStatus`, and reconnects only when the answer is missing or stale. It releases the gate before returning so the expensive part of the request (the actual Exchange read) does not hold the lock. The sample HTTP function then calls `Get-AcceptedDomain` outside the critical section and returns connection metadata alongside the domain list.

```powershell
$connectionStatus = Assert-ExchangeOnlineConnection
$domains = @(Get-AcceptedDomain | Select-Object DomainName, DomainType, Default)
```

That split matters. The lock protects connect and refresh. It does not serialize every Exchange cmdlet. You want concurrency for the read; you want a single-file line for the reconnect.

![HTTP response listing accepted domains](images/05-test-exchange-connection-response.png)

*Capture: Browser or REST client response from GET /api/TestExchangeConnection showing connectionAction, tokenStatus, and acceptedDomains.*

## Why the lock has to be static

In-proc concurrency in the PowerShell worker means more than one runspace can live inside the same process. Each runspace gets its own `profile.ps1` execution. A script-scoped `SemaphoreSlim` created inside the module would be one instance per runspace, which means two cold starts could still call `Connect-ExchangeOnline` at the same time. A static field on a type defined with `Add-Type` is process-wide. Every runspace that imports the module sees the same gate.

```csharp
public static class ExoConnectionGate
{
    public static readonly SemaphoreSlim Instance = new SemaphoreSlim(1, 1);
}
```

That is the entire synchronization story. One permit. Wait, inspect, maybe connect, release. If connect throws, the `finally` still releases so the next caller is not permanently locked out. The Pester suite asserts that failure path explicitly, because a swallowed exception that leaves the gate closed is worse than a noisy reconnect.

The Function App sets `PSWorkerInProcConcurrencyUpperBound` to `2` so the race is real without opening a pile of Exchange sessions. Premium with `minimumElasticInstanceCount: 1` keeps at least one worker warm so the profile investment survives between calls.

## Managed identity and the two permission planes

Connecting with `-ManagedIdentity` is only half of authorization. Entra ID still needs the managed identity to hold `Exchange.ManageAsApp` on the Office 365 Exchange Online resource. Exchange Online itself still needs the identity registered as an application service principal and assigned a management role. This sample uses `View-Only Configuration` so `Get-AcceptedDomain` works without turning the Function App into an Exchange Administrator.

![Identity blade with system-assigned identity On](images/02-system-assigned-identity.png)

*Capture: Function App → Identity → System assigned, Status On, with the Object (principal) ID visible.*

![Enterprise app permission Exchange.ManageAsApp](images/03-exchange-manage-as-app.png)

*Capture: Entra ID → Enterprise applications → the Function App identity → Permissions, showing Exchange.ManageAsApp granted on Office 365 Exchange Online.*

![Get-ManagementRoleAssignment for the managed identity](images/04-view-only-configuration-role.png)

*Capture: Exchange Online PowerShell output of Get-ManagementRoleAssignment for the managed identity object Id, showing View-Only Configuration.*

The grant script is intentionally separate from the zip deploy. Infrastructure creates the identity. Permissions attach Exchange rights to that identity. Code deploy only pushes `FunctionApp/`. Mixing those steps hides which plane failed when the smoke test returns 500.

## Watching reuse and refresh

Once the Function App is warm, the first call after a cold start should log a refresh or a profile connect. Later calls on the same worker should log reuse. That contrast is the whole point of the design: you paid for the managed-identity handshake once, and the SemaphoreSlim kept two runspaces from paying twice at the same time.

![Log stream contrasting a reused session with a refresh](images/06-log-stream-reuse-vs-refresh.png)

*Capture: Function App log stream or Application Insights traces showing one line for “connection reused (TokenStatus Active)” and another for “connection missing or expired; refreshing.”*

Deploy order stays simple. Bicep builds the Windows EP1 Function App with PowerShell 7.6 and `EXCHANGE_ORGANIZATION`. The grant script adds `Exchange.ManageAsApp` and `View-Only Configuration`. The zip deploy publishes the profile, the module, and the smoke-test function. Then you hit `/api/TestExchangeConnection` with a function key and read accepted domains from an identity that never held a secret.
