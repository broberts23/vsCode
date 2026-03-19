# Why securing Microsoft Graph Command Line Tools matters

## Introduction

Graph PowerShell is one of the most convenient ways to work with Microsoft Graph. It's also one of the easiest ways to accidentally expand what a user can read or change across your tenant.

If you've ever run `Connect-MgGraph`, signed in successfully, and still hit "Insufficient privileges", you're in good company. The missing piece is usually that delegated permissions are not just about "your user" or "the cmdlet" - they're about the combination of:

> [Screenshot placeholder: PowerShell terminal showing a bright red "Insufficient privileges" error after a Connect-MgGraph attempt. This validates the reader's pain point immediately.]

- the **client application** you're signing in with (for Graph PowerShell default sign-in, "Microsoft Graph Command Line Tools"), and
- the **user** who signed in.

Once you keep those two things together, the whole delegated permission story gets more predictable. And once you factor *security* into that model, it gets obvious why "Microsoft Graph Command Line Tools" is worth treating like a privileged admin tool in your tenant.

## The security risk: what happens when you admin-consent high-privilege scopes

`Connect-MgGraph` uses a client application context to request tokens. When you authenticate with Graph PowerShell using the default client app, the Entra sign-in is recorded under the enterprise application named **Microsoft Graph Command Line Tools**.

Here's the security punchline: if you grant **admin consent** for high-privilege delegated scopes to Microsoft Graph Command Line Tools, you're not granting those scopes to "a script" - you're granting them to a client app that any allowed user can sign into.

That means a user with **no Entra ID admin roles** can still perform tenant-wide operations that are outside the "standard user" experience if:

- the delegated scope is tenant-wide (example: directory-wide read), and
- Graph doesn't require an admin role for that specific operation, and
- your tenant policies don't block it.

For example, if an admin grants admin consent for `User.Read.All` and/or `Group.Read.All` to Microsoft Graph Command Line Tools, a standard user can request those scopes and enumerate users/groups. This allows any employee to download your entire corporate directory (names, emails, job titles) for phishing reconnaissance, which is normally blocked for standard users in many enterprise organizations.

```powershell
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All"
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName
Get-MgGroup -All | Select-Object DisplayName, Id
```

This doesn't "bypass roles" in general (many endpoints still require specific Entra roles), but it can expand what non-admin users can read through Graph PowerShell if tenant-wide read scopes are admin-consented to the client app.

For write operations, Graph enforces both the delegated scope in the token and the signed-in user's authorization for that specific action (for example, group membership changes require a write scope and the caller being allowed to manage the group). That's exactly why "who can use the client app" is such an important control.

And it isn't just read access. If you admin-consent tenant-wide write scopes (for example, `GroupMember.ReadWrite.All` or `Directory.ReadWrite.All`) to Microsoft Graph Command Line Tools, any user who can sign into the app can request those scopes and attempt write operations from PowerShell. Each request still has to pass Graph's authorization checks (scope + user privilege + policy), but you have increased the population of users who can request and present those scopes to Graph.

## The mental model (three actors)

Every delegated call to Microsoft Graph has three actors involved:

- **Resource API:** Microsoft Graph (the API you're calling)
- **Client app:** Microsoft Graph Command Line Tools (the Entra ID application context `Connect-MgGraph` uses by default)
- **User:** the identity that signed in

Delegated permissions are always "app + user". That's not a philosophical point - it's how Entra ID issues tokens and how Graph authorizes requests.

### Why the client app name matters ("Microsoft Graph Command Line Tools")

When you run `Connect-MgGraph`, you're not just "signing into Graph". You're signing into a client application that requests Microsoft Graph scopes on your behalf.

> [Screenshot placeholder: The Entra admin center 'Enterprise applications' blade showing 'All applications' filtered to 'Microsoft Graph Command Line Tools' to visualize the client app object.]

So when you grant/admin-consent delegated permissions, you're granting them to **Microsoft Graph Command Line Tools** (the Enterprise application / service principal in your tenant). If you grant permissions to some *other* app registration, but still authenticate with the Command Line Tools app, nothing changes for your `Connect-MgGraph` session.

If you intentionally authenticate using a different client app context (for example, your own app registration), then the permissions need to be granted to *that* client instead. The key idea is: permissions follow the client app that requested the token.

If you want to see this object in the UI, look in the Entra admin center under **Enterprise applications** for "Microsoft Graph Command Line Tools".

## Delegated permissions, in one sentence

Delegated permissions are OAuth **scopes** that describe what the client app is allowed to do in Microsoft Graph **on behalf of the signed-in user**.

## What `Connect-MgGraph` is actually doing

At a high level, `Connect-MgGraph`:

1. Signs you in (interactive or device code)
2. Requests one or more **scopes**
3. Receives an **access token** for Microsoft Graph
4. Uses that token on every subsequent Graph request

That access token includes (among other things) the `scp` claim: a space-separated list of delegated scopes that were actually granted. Graph checks those scopes at request time.

Here are two practical commands I use constantly:

```powershell
Connect-MgGraph -Scopes "User.Read.All","Group.Read.All"
Get-MgContext | Select-Object -ExpandProperty Scopes
```

## Requested vs granted vs effective (where most confusion lives)

There are three different "levels" of permission to keep straight:

- **Requested scopes**: what you ask for in `Connect-MgGraph -Scopes ...`
- **Granted scopes**: what Entra ID is willing to issue in the token (based on consent)
- **Effective access**: what you can actually do in Graph, after Graph also considers the signed-in user's roles/privileges and any tenant policies

This is why two people can run the same cmdlet with the same `-Scopes` list and get different results: the *user context* still matters in delegated flows.

## Consent: user consent vs admin consent

Consent answers a simple question: "Is this client application allowed to have this scope in this tenant?"

> [Screenshot placeholder: A side-by-side comparison of the 'Permissions requested' OAuth prompt shown to a standard user vs the 'Admin consent requested' prompt shown for high-privilege scopes. Highlights the difference between the two flows.]

In most tenants:

- Some low-impact scopes can be granted by **user consent** (if user consent is enabled and the permission is eligible for user consent)
- Many org-wide or sensitive scopes require **admin consent**

And again, the consent is tied to the client app. When you use `Connect-MgGraph` with the default client app, that means the consent is tied to the **Microsoft Graph Command Line Tools** Enterprise application in your tenant.

From a security perspective, it's useful to say it more bluntly:

- **Admin consent is a tenant-wide decision about an application.**
- Once a delegated scope is admin-consented for Microsoft Graph Command Line Tools, the remaining question becomes: "Which users are allowed to sign into this app and request that scope?"

### Gotcha: "I added permissions in Entra but it still fails"

If you added delegated permissions to a custom app registration, but you're authenticating with `Connect-MgGraph` using the default client app, your token request is still coming from **Microsoft Graph Command Line Tools**.

In that situation, you need to either:

- grant/admin-consent the required scopes to Microsoft Graph Command Line Tools, or
- authenticate with your custom app registration (so the token request comes from that client instead)

### Another gotcha: "I made them User (or Group) Administrator, so why don't they have `User.ReadWrite.All` / `Group.ReadWrite.All`?"

This one is *extremely* common when people are new to Graph PowerShell.

Giving a user an Entra built-in role like **User Administrator** or **Groups Administrator** changes what that user is allowed to do in the directory. It does **not** magically add delegated Graph scopes to your `Connect-MgGraph` session.

Think of it like two separate gates you have to pass through:

1. **Scopes gate (delegated permissions):** the access token must contain the delegated scope (like `User.ReadWrite.All`), and that scope must be consented for the client app (Microsoft Graph Command Line Tools when using the default client app).
2. **Privilege gate (who the user is):** the signed-in user still needs the right admin role/privileges to perform the action.

So yes: assigning **User Administrator** might be necessary for certain user-management operations, but it is not sufficient. If your token only has `User.Read` (the default in many examples), Graph will still block write operations because the scope isn't there.

### Scenario: `Directory.ReadWrite.All` is admin-consented, but the user is only "User Administrator"

This scenario shows why admin consent and role assignment are separate controls.

Setup:

- An admin has granted **admin consent** for `Directory.ReadWrite.All` to **Microsoft Graph Command Line Tools**.
- The user is assigned the **User Administrator** Entra role.

#### What still trips people up (and how to verify it)

Even with admin consent in place, the user still has to **request** the scope at sign-in time. If they run `Connect-MgGraph` without `-Scopes`, they may not get `Directory.ReadWrite.All` in their token.

```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes "Directory.ReadWrite.All"
Get-MgContext | Select-Object -ExpandProperty Scopes
```

If `Get-MgContext` doesn't show `Directory.ReadWrite.All`, any directory write call will fail regardless of the user's role.

#### Concrete example: can they run `New-MgGroup`?

Yes, if both gates are satisfied:

1. **Scope gate:** the token contains a write scope that covers groups (commonly `Group.ReadWrite.All` or `Directory.ReadWrite.All`).
2. **Privilege/policy gate:** the user is allowed to create the type of group you're creating (tenant settings can restrict group creation).

With `Directory.ReadWrite.All` in the token, Graph has the scope it needs for a group create request. The request will still fail if group creation is restricted by tenant policy for that user (for example, Microsoft 365 group creation restrictions).

> [Screenshot placeholder: `Get-MgContext` showing `Directory.ReadWrite.All`]
>
> [Screenshot placeholder: Tenant setting restricting group creation (if applicable)]

If you want to make this section very real in the post, you can show a "known good" group create call right after you connect:

```powershell
# Security group example
New-MgGroup -DisplayName "Demo Security Group" -MailEnabled:$false -MailNickname "demoSecurityGroup" -SecurityEnabled:$true
```

#### Why `Directory.ReadWrite.All` still isn't "everything"

Even when it's granted and present in the token, `Directory.ReadWrite.All` doesn't replace other Graph permission families, and it doesn't override the user's role requirements. For example, these require different delegated scopes (and often different Entra roles too):

- **Conditional Access** changes: `Policy.ReadWrite.ConditionalAccess` + Conditional Access Administrator (or higher)
- **Directory role management (PIM / role assignments)**: `RoleManagement.ReadWrite.Directory` + Privileged Role Administrator (or higher)
- **App registrations / service principals** management: `Application.ReadWrite.All` (and/or related scopes) + Application Administrator (or higher)

So the pattern to remember is: admin consent + a tenant-wide scope can reduce "missing scope" failures, but every operation still has to pass **(scope required by the endpoint)** and **(user allowed to do it)**.

## How to secure Microsoft Graph Command Line Tools (step-by-step)

### Step 0 (recommended): Restrict who can sign into the app

Before you add more delegated permissions to Microsoft Graph Command Line Tools, decide who is allowed to authenticate with it. This is the difference between "admin-consenting a tool for the admin team" and "admin-consenting a tool for the whole tenant".

Two high-impact controls:

- **Require assignment** for the enterprise application and only assign an admin group.
- **Conditional Access** policy scoped to the app (MFA, compliant device, trusted location, etc.). Note that "Microsoft Graph Command Line Tools" is a **Public Client** (native app), which limits some CA controls (e.g., non-interactive flows); focusing on MFA and device compliance is key here.

When **Assignment required?** is enabled, only assigned users/groups can access the app, and users can't self-consent to it.

> [Screenshot placeholder: Microsoft Graph Command Line Tools - Properties - "Assignment required"]
>
> [Screenshot placeholder: Microsoft Graph Command Line Tools - Users and groups assignments]
>
> [Screenshot placeholder: Conditional Access policy targeting Microsoft Graph Command Line Tools]

Suggested implementation steps:

1. Create a security group (example: `GraphCommandLineTools-Allowed`).
2. In **Entra admin center** -> **Enterprise applications** -> **Microsoft Graph Command Line Tools**:
   - Set **Assignment required?** to **Yes**.
   - Assign the `GraphCommandLineTools-Allowed` group under **Users and groups**.
3. Create a Conditional Access policy targeting **Microsoft Graph Command Line Tools** that requires MFA (and, ideally, compliant/managed devices).

If you skip this step and you admin-consent tenant-wide delegated scopes, you're relying on "whoever can run PowerShell" as an access control boundary.

### Step 1: Request the scope in PowerShell (so it's even eligible to be in the token)

```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.ReadWrite.All"
Get-MgContext | Select-Object -ExpandProperty Scopes
```

If the sign-in succeeds and `Get-MgContext` shows `User.ReadWrite.All`, great. If you get a consent/authorization error, move to Step 2.

### Step 2: Review/grant consent to Microsoft Graph Command Line Tools (Entra admin center)

You do this in the Entra admin center by granting the delegated permissions to the **Enterprise application** named "Microsoft Graph Command Line Tools".

> [Screenshot placeholder: Entra admin center - Home]
>
> [Screenshot placeholder: Enterprise applications - search "Microsoft Graph Command Line Tools"]

High-level steps:

1. Go to **Entra admin center**.
2. Open **Enterprise applications**.
3. Find and open **Microsoft Graph Command Line Tools**.
4. Open the permissions/consent page (**Permissions** or **Security > Permissions**).
5. Review the permissions the app is requesting, then grant admin consent if appropriate (example: `User.ReadWrite.All`, `Group.ReadWrite.All`).
6. Choose **Grant admin consent** for your tenant (if required).

> [Screenshot placeholder: Microsoft Graph Command Line Tools - Permissions page]
>
> [Screenshot placeholder: Grant admin consent prompt/result]

Security note: treat every delegated scope you add here as "available to every user who can sign into this app". That makes this an application hardening decision, not a script troubleshooting step.

Before you add anything new, it's worth doing a quick "permission hygiene" pass:

- Review what Microsoft Graph delegated scopes are already granted to the app.
- Remove anything you don't actively need.
- Be especially cautious with tenant-wide write scopes (examples: `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Policy.ReadWrite.ConditionalAccess`, `Application.ReadWrite.All`).

### Admin consent vs user consent (using the scenario above)

In practice:

- Use **admin consent** when the scope is high privilege (like directory-wide read/write) or when your tenant blocks user consent (for example, `User.ReadWrite.All` and `Group.ReadWrite.All`).
- Use **user consent** only when (a) the scope is eligible for user consent and (b) your tenant allows it, and (c) you're comfortable with users granting that permission to the client app.

Even when user consent is technically possible, many organizations choose admin consent for anything beyond low-impact scopes so there's a clear approval trail.

### Step 3: Reconnect and verify (don't skip this)

After consent is granted, reconnect and verify the granted scopes again:

```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All"
Get-MgContext | Select-Object -ExpandProperty Scopes
```

If the scopes show up and the user has the appropriate Entra role, your write operations should start behaving the way you expected.

### Step 4: Secure tenant consent settings (so users can't self-expand)

Even if you lock down the enterprise app, it's still worth tightening tenant consent behavior so users can't freely grant new delegated permissions to other apps (or request high-privilege delegated permissions through ad-hoc tools).

Hardening moves:

- Disable user consent, or limit it to verified publishers and low-impact permissions.
- Enable the admin consent workflow so non-admin users can request access without teaching them to "click accept" on random consent prompts.

> [Screenshot placeholder: Consent and permissions - User consent settings]
>
> [Screenshot placeholder: Consent and permissions - Admin consent workflow settings]

### Example: why `New-MgGroupMemberByRef` is a good canary

Adding group members is a simple action with outsized impact. If you admin-consent group write scopes to Microsoft Graph Command Line Tools and you don't restrict who can use the app, you've made group membership changes possible from PowerShell for a much wider audience than "just the admin team".

Under the hood, this is the Microsoft Graph "add member" operation (`POST /groups/{id}/members/$ref`). In delegated scenarios, Graph requires an appropriate delegated scope (commonly `GroupMember.ReadWrite.All`) and also requires the signed-in user to be allowed to do the action (for example, a group owner or a supported Entra role). Role-assignable groups have additional requirements.

For the Graph PowerShell v1.0 cmdlet, the pattern is:

```powershell
Connect-MgGraph -Scopes "GroupMember.ReadWrite.All"

$groupId = "<group-guid>"
# Note: This must be the Object ID (GUID) of the user/group, not the UPN/name
$memberId = "<user-or-group-object-guid>"

$body = @{
  "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$memberId"
}

New-MgGroupMemberByRef -GroupId $groupId -BodyParameter $body
```

For the call to succeed, both must be true:

- the delegated scope in the token (for example, `GroupMember.ReadWrite.All`), and
- the signed-in user's allowed privileges (for example, being a group owner, or holding a supported Entra role)

### What this looks like in Entra logs

When a user signs in with `Connect-MgGraph` using the default client app, you'll see a sign-in event for **Microsoft Graph Command Line Tools** in the **sign-in logs**, with **Microsoft Graph** as the target resource.

To find it:

1. Entra admin center -> **Monitoring & health** -> **Sign-in logs**
2. Filter **Application** = "Microsoft Graph Command Line Tools"
3. Open the event and review the **Conditional Access** and **Authentication Details** tabs (useful to prove your app-specific CA policy is working)

> [Screenshot placeholder: Sign-in logs filtered to Application = "Microsoft Graph Command Line Tools"]
>
> [Screenshot placeholder: Sign-in event details showing Conditional Access policies applied]

When `New-MgGroupMemberByRef` succeeds, you should also see an entry in the **audit logs** for a group membership change (for example, an operation named "Add member to group"), showing:

- **Initiated by**: the signed-in user
- **Target resources**: the group and the member object
- **Additional details**: look for identifiers for the group and the added member

To find it:

1. Entra admin center -> **Monitoring & health** -> **Audit logs**
2. Filter for group membership activities (start with "Add member to group")
3. Open the event and confirm **Initiated by** and **Target resources**

> [Screenshot placeholder: Audit logs entry for group membership change]

If you're troubleshooting a failure (or validating that your hardening changes are working), the next sections explain how Graph enforces delegated permissions, how Conditional Access affects sign-in, and how to troubleshoot.

## Delegated scopes aren't the whole story

Even with the right scopes in the token, Graph may still deny an action. That's because delegated access is constrained by both:

- the **scopes** (`scp`) in the token, and
- the **signed-in user's privileges** (Entra roles, resource ownership, Graph RBAC where applicable), plus tenant policies

For example:

- You might have `Group.ReadWrite.All`, but a tenant policy could block group creation for your user.
- You might have a directory-read scope, but some endpoints still require the user to hold a specific admin role to read certain data.

## What enforces what (and when)

It helps to separate responsibilities:

- **Entra ID** authenticates the user and issues tokens for the requested resource (Microsoft Graph)
- **Microsoft Graph** authorizes each request at runtime by checking scopes, user context, and policy controls

Tokens are necessary, but not sufficient.

## Conditional Access and MFA (why automation "suddenly" breaks)

Conditional Access (CA) can change the sign-in experience and break scripts that assume a silent login. CA can require MFA, restrict sign-ins by device/location, or enforce compliant devices.

When that happens, you might see interactive prompts (or device code requirements) before you ever reach a Graph API call.

## How to figure out which scopes you actually need

Graph PowerShell cmdlets are wrappers over Microsoft Graph endpoints. The required delegated scopes come from the underlying endpoint, not from the cmdlet name.

The workflow I recommend is:

1. Decide what you're trying to do (endpoint / data)
2. Check what delegated permissions that endpoint requires
3. Request the smallest scope set in `Connect-MgGraph -Scopes ...`
4. Confirm what you actually got via `Get-MgContext`

Remember: if you're using `Connect-MgGraph` with the default client app, those permissions need to be granted to **Microsoft Graph Command Line Tools**.

## Troubleshooting (quick checklist)

When something fails, I usually walk this list in order:

1. Did I sign into the right tenant and the right account?
2. Do I have the scopes I think I have? (`Get-MgContext`)
3. Has consent been granted for those scopes to the right client app (Microsoft Graph Command Line Tools when using the default client app)?
4. Does the signed-in user have the required role/privilege for this specific action?
5. Is Conditional Access changing or blocking the sign-in?

Useful reset commands:

```powershell
Get-MgContext | Format-List
Disconnect-MgGraph
Connect-MgGraph -Scopes "User.Read" -TenantId "<tenant-guid>"
```

## Security checklist (recap)

If you're turning a one-off command into a runbook, the risk profile changes. But even before you get to "automation", remember that Microsoft Graph Command Line Tools is a shared client app: whatever you admin-consent to it can become available to any user who can authenticate with it and request the scope.

A few guardrails help a lot:

- Request the smallest scope set that gets the job done
- Prefer short-lived sessions (connect, do the work, disconnect)
- Avoid high-privilege scopes in shared automation accounts unless there's a clear business need and review process
- Limit who can sign into the enterprise application (assignment required + group assignment where feasible)
- Apply Conditional Access specifically to the app (MFA/compliant device/trusted locations)
- Review and remove unused delegated permission grants from the app regularly
- If you need tenant-wide permissions for automation, consider using a dedicated app registration instead of over-consenting Microsoft Graph Command Line Tools

## Conclusion

When you use `Connect-MgGraph` with the default client app, you're authenticating through **Microsoft Graph Command Line Tools**, and delegated permissions are evaluated as "client app + user". That one idea explains most "why doesn't this work" moments - and most "how did this user get access to that?" moments too:

- If the right scopes aren't granted (consented) to the client app, they won't appear in the token.
- If the user doesn't have the necessary privileges (or policy blocks it), Graph will still deny the request.

So treat Microsoft Graph Command Line Tools like what it really is: a privileged administrative client. Keep its consent grants tight, and make sure only the right people (and devices) can use it.

## Reference links

- Microsoft Graph PowerShell SDK overview: <https://learn.microsoft.com/powershell/microsoftgraph/overview>
- `Connect-MgGraph` documentation: <https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph>
- Restrict access to an enterprise app (assignment required, user/group assignment): <https://learn.microsoft.com/entra/identity/enterprise-apps/manage-user-access-to-apps>
- Enterprise app properties (assignment required behavior): <https://learn.microsoft.com/entra/identity/enterprise-apps/application-properties>
- View enterprise app permissions and consent: <https://learn.microsoft.com/entra/identity/enterprise-apps/view-app-permissions>
- Configure user consent settings: <https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent>
- Configure admin consent workflow: <https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow>
- Microsoft identity platform permissions & consent overview: <https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview>
- Microsoft Graph permissions reference: <https://learn.microsoft.com/graph/permissions-reference>
- Graph API - list users (example of a tenant-wide delegated read): <https://learn.microsoft.com/graph/api/user-list>
- Graph API - add member to group (`POST /groups/{id}/members/$ref`): <https://learn.microsoft.com/graph/api/group-post-members>
- Graph PowerShell - `New-MgGroupMemberByRef`: <https://learn.microsoft.com/powershell/module/microsoft.graph.groups/new-mggroupmemberbyref>
- Access tokens (claims like `scp`): <https://learn.microsoft.com/entra/identity-platform/access-tokens>
- Conditional Access overview: <https://learn.microsoft.com/entra/identity/conditional-access/overview>
- Sign-in logs overview: <https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins>
- Audit logs overview: <https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs>
