# The dMSA Migration Factory: How Windows Server 2025 Finally Fixed Service Accounts

Every infrastructure engineer has a story about a service account. Maybe it was the SQL Server Agent credential whose password expired on a Friday night, taking down a production ETL pipeline. Maybe it was the discovery that some internal LOB application had been running as a domain admin for seven years because "that's what the vendor told us to do." Or maybe it was the audit finding that flagged thirty-four service accounts with passwords that hadn't been rotated since Rudd was PM.

The problem has never been that service accounts are conceptually hard. The problem is that the operational overhead of managing them — password rotation, SPN registration, delegation configuration, principal-of-least-privilege enforcement, lifecycle management — has always been just painful enough that teams defaulted to the path of least resistance. And that path usually ended with a service running as LocalSystem or NetworkService, or worse, as a domain user account with a password set to never expire. 🔥

Windows Server 2025 introduced delegated Managed Service Accounts (dMSAs), and with them, a genuinely new approach to an old problem. This is the story of what dMSAs are, why they're a meaningful improvement over both traditional service accounts and group Managed Service Accounts, and how you can build an automated pipeline to migrate existing services onto them without spending your weekend manually clicking through Active Directory Users and Computers.

## The Pre-dMSA World

To understand why dMSAs matter, you have to unpack the pain they're designed to eliminate.

A traditional service account is, for all practical purposes, just a regular domain user account that happens to be running a Windows service. You create the user, set a password, log into the target machine, and configure the service's Log On As property to point at that user. Every ninety days (or whatever your password policy dictates), the password changes, and every service using that account breaks simultaneously until someone updates it. There are workarounds — managed service accounts in earlier Windows versions, third-party password management tools, scheduled scripts that rotate credentials — but every workaround introduces its own surface area for failure.

Group Managed Service Accounts (gMSAs), introduced in Windows Server 2012, were a genuine leap forward. The domain controller automatically manages the password. No human ever needs to know or rotate it. Multiple servers can use the same gMSA. The service starts up, the machine retrieves the current password from Active Directory via a secure channel, and authentication just works. For many organizations, gMSAs became the gold standard for service identity management.

But gMSAs have a constraint that starts to chafe at scale: they require a domain administrator to create them. The `New-ADServiceAccount` cmdlet, when used with the `-GroupManagedServiceAccount` switch, demands privileges that most service owners simply don't have. In practice, this means a ticket, a change request, a trip through the identity team's queue, and a lead time measured in days and weeks. For a Dev team spinning up a new microservice, that friction is often enough to make them reach for a local account instead.

## Finding Legacy Services

The first step in any migration is to understand the scope of the problem. The Migration Factory project includes a `GET /api/inventory` endpoint that takes a hostname and returns a list of all Windows services running on that machine, along with their current logon account. This is implemented as an Azure Function that invokes a PowerShell script over WinRM/TLS:

```python
def discover_services(runner: ScriptRunner, host: str) -> InventoryResult:
    result = runner.run_script(
        "Discover-WindowsServices.ps1", {"ComputerName": host})
    require_success(result)
    raw_payload = json.loads(result.stdout or "[]")
    if isinstance(raw_payload, dict):
        raw_payload = [raw_payload]
    per_user_svc_pattern = re.compile(r'_[a-f0-9]{5}$', re.IGNORECASE)
    filtered_payload = [
        svc for svc in raw_payload if not per_user_svc_pattern.search(svc.get("Name", ""))]
    return inventory_result_from_payload(host=host, payload=filtered_payload)
```

In the screenshot below, you can see the output of that inventory operation for a lab VM. The `start_name` column shows the current identity for each service. The `LegacyCustomService` service is running as a traditional domain user account, which is exactly the kind of account we want to migrate to a dMSA.

![alt text](image.png)

## Enter the Delegated MSA

The dMSA model in Windows Server 2025 flips the permission model on its head. Instead of requiring a domain admin to create the account, the `New-ADServiceAccount` cmdlet with the `-CreateDelegatedServiceAccount` flag lets the account be created by any authorized principal - as long as that principal has been delegated the right to do so. The domain admin defines the policy once (who can create dMSAs, which machines can use them, what naming conventions apply), and then service owners operate entirely within those guardrails.

```powershell
New-ADServiceAccount `
    -Name "svc-spooler-dmsa" `
    -DNSHostName "svc-spooler-dmsa.contoso.local" `
    -CreateDelegatedServiceAccount `
    -PrincipalsAllowedToRetrieveManagedPassword "server2025" `
    -KerberosEncryptionType AES128,AES256

Set-ADServiceAccount -Identity $Name -Replace @{ "msDS-DelegatedMSAState" = 3 } -ErrorAction Stop
```

Notice what's missing from that invocation: there's no password flag, no manual credential generation, no input from a human who might paste a secret into a shared document. The domain controller handles password management transparently, exactly the way it does for gMSAs. The innovation is purely in the delegation model — who is allowed to call this cmdlet and under what circumstances.

The `-PrincipalsAllowedToRetrieveManagedPassword` parameter binds the dMSA to specific machine accounts, just like gMSA. Only those servers can pull the account's current password from the directory. This means even if an attacker compromises a machine in the fleet, they can't extract credentials for dMSAs that were delegated to other hosts. The blast radius is bounded by design.

## Why This Changes the Migration Calculus

The automation implications are where dMSAs really start to shine. Because the creation operation no longer requires an elevated escalation, you can safely embed it in an automated pipeline. An Azure Function, running as a service account with precisely scoped AD delegation rights, can inventory a VM's Windows services, create the appropriate dMSA for each one, reconfigure the service logon, restart the service, and validate that it's running under the correct identity — all without a human in the loop.

But the architecture has a hard constraint that only reveals itself when you actually try to run this: **dMSAs do not work on domain controllers**. You cannot configure a domain controller's local services to run as a dMSA. The SCM on a domain controller does not support the managed password protocol that dMSAs rely on. This is not a bug - it's a design boundary. Because dMSAs rely on computer-bound Kerberos token requests, a domain controller cannot perform the necessary loopback authentication to its own KDC to retrieve the account keys. Every configuration command succeeds silently, but the service will fail to start.

The implication for automation is that you need two distinct execution targets: a domain controller for the AD provisioning steps (`New-ADServiceAccount`, `Set-ADServiceAccount`, `Start-ADServiceAccountMigration`), and a member server/s for the local service configuration steps (`Set-ItemProperty` on the registry, `Invoke-CimMethod` on the Win32_Service class). The Migration Factory handles this by accepting both `domainController` and `targetHost` in the migration request, and spawning two separate WinRM runners:

```python
dc_runner = WinRMPowerShellRunner(
    request.domain_controller, config, request.domain_controller_thumbprint)
member_runner = WinRMPowerShellRunner(
    request.target_host, config, request.target_host_thumbprint)

create_result = create_dmsa(dc_runner, request, unique_dmsa_name)
migration_result = migrate_service(member_runner, request, unique_dmsa_name)
```

The split is not theoretical. The `Create-DMSA.ps1` script runs on the DC and touches nothing but Active Directory — no registry keys, no WMI, no service control manager. The `Configure-WindowsService.ps1` script runs on the member server and does exactly the opposite: sets the `DelegatedMSAEnabled` registry key, configures the service via WMI, and never imports the ActiveDirectory module. They are separate concerns that happen to share a mission.

The `migrate_service` domain function encapsulates the member-server side of the split, and it has two distinct behaviors depending on whether this is a standalone or superseding migration:

```python
def migrate_service(runner: ScriptRunner, request: MigrationRequest, unique_dmsa_name: str) -> MigrationResult:
    netbios_domain = request.domain_dns_name.split(".")[0].upper()
    params: dict[str, object] = {
        "ServiceName": request.service_name,
    }

    if not request.superseded_account:
        params["AccountName"] = f"{netbios_domain}\\{unique_dmsa_name}$"

    result = runner.run_script("Configure-WindowsService.ps1", params)
    require_success(result)
    return MigrationResult(request.service_name, unique_dmsa_name, True, result.stdout.strip() or "service migrated")
```

That `AccountName` parameter carries a subtlety that cost me a few rounds of troubleshooting. The Service Control Manager expects the domain component in **NetBIOS** form — `CONTOSO\svc-dmsa$`, not `contoso.local\svc-dmsa$`. The FQDN form looks correct in every config dialog and logs without error, but the service will fail to start because the SCM can't resolve the identity against the domain. The `split('.')[0].upper()` call extracts the NetBIOS prefix from the DNS domain name, and it's one of those two-line fixes that changes the entire behavior of the pipeline.

For the superseding migration path — where the dMSA replaces an existing domain user account through AD metadata rather than a logon change — the member server's job is narrower. The `Start-ADServiceAccountMigration` cmdlet runs on the domain controller, inside `Create-DMSA.ps1`, linking the dMSA directly to the existing account's distinguished name:

```powershell
if ($SupersededAccount) {
    Start-ADServiceAccountMigration -Identity $Name -SupersededAccount $SupersededAccount -Server localhost -ErrorAction Stop
    "dMSA $Name created superseding $SupersededAccount"
}
```

The service's current logon identity remains completely unchanged. The SCM transparently resolves through the dMSA's supersession link, and the `-PrincipalsAllowedToRetrieveManagedPassword` binding on the dMSA tells AD which machine is authorized to pull the password. On the member server side, the only prerequisite is the `DelegatedMSAEnabled` registry key — no WMI service reconfiguration, no logon change, no restart. Which is exactly what `Configure-WindowsService.ps1` does when called without an `AccountName` parameter: it sets the registry key and returns.

The PowerShell service configuration script has its own evolution story. The earliest version relied on `sc.exe config` to set the service logon:

```powershell
& sc.exe config $ServiceName obj= $AccountName password= ""
```

But `sc.exe` has a temperamental relationship with argument parsing in remote PowerShell contexts. The space-delimited `obj=` and `password=` syntax is easy to get wrong, and failure modes tend to be silent — the command exits with a nonzero code but the error message is cryptic at best. The current version uses the WMI `Change` method via `Invoke-CimMethod`, which accepts structured, named arguments instead of positional shell tokens:

```powershell
$CimService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
$Result = Invoke-CimMethod -InputObject $CimService -MethodName Change -Arguments @{
    StartName     = $AccountName
    StartPassword = ""
}
if ($Result.ReturnValue -ne 0) {
    throw "Failed to configure $ServiceName to run as $AccountName. WMI Error Code: $($Result.ReturnValue)"
}
```

The hashtable-based `Arguments` parameter eliminates the quoting ambiguity entirely. If the configuration fails, `$Result.ReturnValue` gives you a meaningful error code instead of `LASTEXITCODE`. And the empty `StartPassword` string still triggers the same managed password protocol that makes dMSAs work — the SCM negotiates with the domain controller on the machine's behalf, and the secret never crosses the wire in a form a human could capture.

One more trap worth calling out: the `-DNSHostName` parameter on `New-ADServiceAccount`. It is **not** the server's FQDN. It is the service account's own pseudo-FQDN DNS host name. I spent an embarrassing amount of time debugging why the account creation returned success but the account metadata looked wrong. The `-DNSHostName` field in AD is a property of the account object, not a routing hint. Give it the domain.

There is also a step in `Create-DMSA.ps1` that is easy to overlook because it happens silently on the DC and you will not see the failure until the service refuses to start on the member server:

```powershell
Add-ADGroupMember -Identity "dMSA-Service-Hosts" -Members "$Name$"
```

This strategy relies on nesting the dynamic dMSA account inside a manually created global security group, such as `dMSA-Service-Hosts`. This group is explicitly assigned the Log on as a service user right (SeServiceLogonRight) within a Group Policy Object (GPO) targeting the host machines—specifically under `Computer Configuration \ Policies \ Windows Settings \ Security Settings \ Local Policies \ User Rights Assignment`. Without this group membership, the Service Control Manager (SCM) on the target host will reject the dMSA's attempt to spin up a service process. When a service initializes, the SCM runs a synchronous access check; if the executing identity lacks SeServiceLogonRight, the launch fails immediately with a 1069 Logon Failure (ERROR_SERVICE_LOGON_FAILED). By pre-authorizing this static group via Group Policy once, newly provisioned, dynamically named dMSAs inherit the necessary logon rights instantly via standard Active Directory group membership evaluation, completely bypassing the latent replication and processing delays associated with running gpupdate /force mid-deployment.

## The Safety Net

Any migration pipeline that doesn't have a rollback mechanism is not a migration pipeline — it's a gamble. The Migration Factory includes a `POST /api/rollback` endpoint that reverses the service logon change and validates that the service comes back up under its previous identity. But rollback for dMSAs is not simply running the forward pipeline in reverse. There are two distinct operations to undo, and they live on different servers.

For the member server, `Configure-WindowsService.ps1` accepts a `-ClearDMSA` switch that removes the `DelegatedMSAEnabled` registry key before reconfiguring the service back to its previous account:

```python
def rollback_service(runner: ScriptRunner, request: RollbackRequest) -> RollbackResult:
    result = runner.run_script(
        "Configure-WindowsService.ps1",
        {
            "ServiceName": request.service_name,
            "AccountName": request.previous_account,
            "ClearDMSA": True,
        },
    )
    require_success(result)
    return RollbackResult(request.service_name, request.previous_account, True, result.stdout.strip() or "service rolled back")
```

For the domain controller side — if the migration used the superseding path (`Start-ADServiceAccountMigration` was called) — the rollback must undo that AD link. A separate script, `Undo-DMSA.ps1`, runs on the DC and calls `Undo-ADServiceAccountMigration`:

```powershell
Undo-ADServiceAccountMigration -Identity $Identity -SupersededAccount $SupersededAccount -Server localhost -ErrorAction Stop
```

The rollback handler in the function app checks whether the original migration was a superseding one by inspecting the presence of `domainController`, `dmsaName`, and `supersededAccount` on the rollback request. If all three are present, it spawns a DC runner, runs the undo script, and only then proceeds to the member server for the local cleanup. The `previousAccount` field in the rollback request carries the original identity — `LocalSystem`, `NetworkService`, or `CONTOSO\legacy-svc` — and it is passed through directly without any NetBIOS transformation because it is already in the form the SCM expects.

In a production system you would derive the rollback fields from the inventory scan rather than trusting user input, but for a lab PoC the pattern is clear: every forward operation has a symmetric reverse operation, and both are validated the same way.

## What Production Looks Like

The PoC intentionally skips several layers of hardening that a real deployment would need. The WinRM connection disables CA validation because the lab uses self-signed certificates — in production you would pin to a specific certificate thumbprint or use a proper PKI. The function app's service account credentials live in `local.settings.json` during development; in production they would move to Azure Key Vault with a managed identity binding. The inventory data lands nowhere persistent; a real system would write it to a database or a log analytics workspace for audit trails and drift detection.

The dual-runner pattern (a DC runner for AD operations and a member-server runner for SCM operations) is one of those architectural decisions that looks like overkill until you try the alternative. Every script that imports the ActiveDirectory module must run on the DC. Every script that touches `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` or `Win32_Service` must run on the member server. There is no overlap. The Automation Factory enforces this at the runner level, not at the script level, so the separation is testable: each domain function accepts a generic `ScriptRunner` protocol, and the unit tests verify call parameters without needing any machines at all.

But the core automation pattern (inventory -> create dMSA -> configure service -> restart/validate -> rollback) is production-viable as a pipeline. The dMSA delegation model makes it possible to run this as a self-service workflow. A service owner submits a migration request, the function app validates the inputs, creates the dMSA, reconfigures the service, and reports back. No domain admin ticket required. No password rotation schedule to maintain. No spreadsheets tracking which services run as what.

Windows Server 2025 didn't invent managed service accounts. It inherited a decade of incremental improvement on an idea that Microsoft first shipped with Windows Server 2008 R2. What it added was the final piece that makes the whole concept work at organizational scale: the ability to delegate creation without compromising control. The dMSA model recognizes that the bottleneck in service identity management has never been the technology — it's been the permission boundary. By moving that boundary to where it belongs, between policy and operation rather than between operator and tool, dMSAs turn a manual, ticket-driven process into something you can automate with a few hundred lines of Python and PowerShell.

The Migration Factory is just one expression of that idea. But it's a concrete one, and it runs. 🚀

## References

- [Microsoft Docs: Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa)
