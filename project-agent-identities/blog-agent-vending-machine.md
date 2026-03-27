# The Agent Vending Machine: Dispensing Governed Agents on Demand

The first blog established why Microsoft Entra Agent ID matters and how to think about governance as a path to success. The next logical question is operational: once you agree that agents need blueprints, sponsors, access packages, Conditional Access, lifecycle, and monitoring, how do you actually turn that model into a repeatable provisioning system?

This is where an agent vending machine becomes useful.

The idea is simple. Instead of asking every team to handcraft an app registration, pick permissions, guess the right authentication flow, negotiate access manually, and then remember to wire in governance later, you provide a controlled service that dispenses a pre-governed agent SKU. The user requests an agent by supplying a small input payload. The service then maps that request to a vetted blueprint, a known authentication posture, a bounded authorization model, and a matching access package. In other words, the vending machine does not dispense random agents. It dispenses governed agents.

## What the System Does

The scaffold in this folder implements that idea as a PowerShell Azure Functions application with HTTP triggers. It is split into two logical actions.

`BootstrapOffering` prepares an offer definition. It turns a governed offer entry into a blueprint creation plan, credential plan, principal creation plan, and access package specification.

`DispenseAgent` accepts a request for a specific offer, creates the agent identity from the selected blueprint, and returns the next governance actions required to make the agent usable in a bounded way.

That split matters. Blueprint and catalog setup is typically an administrative, infrequent activity. Dispensing agent instances is an operational activity. If you collapse the two into one opaque script, the whole system becomes harder to govern, audit, and delegate.

## Why PowerShell Functions Fit

There is nothing magical about PowerShell here. The reason to use a PowerShell HTTP-trigger Function App is that it fits the control-plane nature of the work.

The system needs to:

1. accept structured provisioning input
2. validate who is calling the endpoint
3. translate an offer into Microsoft Graph operations
4. call Graph or return a dry-run plan
5. integrate with managed identity and Easy Auth
6. remain easy to read and change by infrastructure and identity teams

PowerShell is good at that kind of orchestration, especially when the surrounding estate already leans on Azure Functions, Entra administration, and Microsoft Graph.

## The Request Contract

The vending machine keeps the request small on purpose. A minimal `DispenseAgent` request looks like this:

```json
{
  "offeringId": "service-desk-mail-triage",
  "instanceDisplayName": "Agent - Service Desk - EMEA - 01",
  "sponsorObjectIds": [
    "11111111-1111-1111-1111-111111111111"
  ],
  "createAgentUser": true,
  "justification": "24x7 shared mailbox triage and incident coordination"
}
```

The caller is not choosing arbitrary permissions, arbitrary roles, or arbitrary auth settings. The caller is choosing a vetted offer. That is the core design decision that keeps the whole model sane.

## The Offer Catalog Is the Product Catalog

The scaffold includes a sample offer manifest at [project-agent-identities/FunctionApp/config/agent-offerings.sample.json](c:/Repo/vsCode/project-agent-identities/FunctionApp/config/agent-offerings.sample.json). That file acts like a product catalog for agent SKUs.

Each offer describes:

1. the blueprint characteristics
2. the supported auth strategy
3. the allowed authorization model
4. the access package that governs resource access
5. whether an agent user is appropriate by default
6. which Work IQ tools fit the scenario

This is what turns the system into a vending machine instead of an ad hoc provisioning endpoint. The catalog is where architecture standards become executable.

## Blueprint Design for the Vending Machine

For a production-oriented vending machine, the blueprint should be designed once and reused many times. Microsoft’s blueprint model is the right place to fix the common traits that every issued agent instance should inherit.

For this system, the blueprint design should include:

1. a clear business-aligned display name and description
2. at least one sponsor and ideally at least one owner
3. managed identity or federated identity credential strategy
4. optional delegated scope exposure if the agent must support on-behalf-of flows
5. a documented set of intended Graph and resource permissions

The scaffold’s `BootstrapOffering` function returns a concrete Graph plan for these steps, including:

1. creating the blueprint application as `Microsoft.Graph.AgentIdentityBlueprint`
2. adding a managed-identity-backed federated identity credential
3. optionally exposing an `access_agent` scope
4. creating the blueprint principal in the tenant

That matches Microsoft’s preview guidance closely enough to be useful without pretending that bootstrap is a one-click production wizard.

## Auth Settings: What This System Assumes

The default assumption in the scaffold is that the Function App itself runs with managed identity and uses App Service Authentication for the HTTP surface.

That gives you two separate trust boundaries:

1. caller authentication to the HTTP endpoint via Easy Auth and an app role such as `Agent.Vending.Admin`
2. Function App authentication to Microsoft Graph via managed identity

For the blueprint itself, the preferred pattern is a federated identity credential backed by Azure-hosted compute. That aligns with Microsoft’s guidance that managed identity or federated credentials are the modern production path, while secrets and certificates remain fallback patterns for local or constrained scenarios.

The scaffold intentionally keeps `function.json` at `anonymous` auth level and expects Easy Auth to sit in front of the endpoint. That is consistent with Azure Functions designs where the app service layer handles authentication and injects the `X-MS-CLIENT-PRINCIPAL` header into the function runtime.

## Permissions and Why the Vending Machine Must Be Opinionated

One of the easiest ways to build a dangerous provisioning service is to let callers request whatever Graph or directory privileges they think they need. That is exactly what this design avoids.

Microsoft explicitly blocks a set of high-risk Graph permissions and high-privilege Entra roles for agents. The authoritative documentation is here:

[Authorization in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/authorization-agent-id)

In particular, Microsoft documents both:

1. the [Microsoft Entra roles allowed for agents](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/authorization-agent-id#microsoft-entra-roles-allowed-for-agents)
2. the [Microsoft Graph permissions for agent IDs](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/authorization-agent-id#microsoft-graph-permissions-for-agent-ids)

That second list is important because it explains what the vending machine must never try to grant. Permissions such as `Application.ReadWrite.All`, `RoleManagement.ReadWrite.All`, `User.ReadWrite.All`, and `Directory.AccessAsUser.All` are blocked because they imply tenant-wide control or broad administrative reach. They are fine examples of the kinds of privileges that should never be available through a self-service agent dispenser.

That is why the offer catalog stores a bounded permission model and a reference to Microsoft’s blocked-permission guidance. The vending machine should not improvise. It should vend only preapproved combinations.

## Access Packages Are the Guardrails, Not a Postscript

The vending machine does not stop after creating an identity. An identity without governed access is just a fast path to sprawl.

Each offer therefore carries an access package design:

1. catalog placement
2. whether the catalog becomes privileged
3. target groups, Entra roles, or API permissions
4. assignment mode
5. assignment policy name
6. lifecycle duration and extension rules

That approach fits Microsoft’s documented model for access packages for agent identities. The package can include group memberships, allowed Entra roles, and API permissions. It cannot be used to assign application roles, SAP roles, or SharePoint Online site roles to agents. The scaffold keeps that limitation visible instead of hiding it.

Operationally, that means the vending machine should work like this:

1. create or identify the agent identity
2. submit or trigger the correct access package assignment path
3. rely on sponsor approval, direct assignment, or agent-requested flow depending on the offer
4. let entitlement management handle expiry and extensions

That is how the agent becomes usable without bypassing governance.

## Agent Users: When the Vending Machine Should Dispense a Digital Worker

Some agents should remain application-shaped. Others need to participate as long-lived collaborators with mailbox, Teams, and user-only resource access. That is the point where the vending machine should support the agent user pattern.

Microsoft’s guidance on agent users makes three points that matter here:

1. the agent user is optional
2. it is linked one-to-one with a parent agent identity
3. it keeps user-context capability while preserving nonhuman security constraints

That makes it a strong fit for offers such as:

1. a service desk digital employee that needs a shared mailbox presence and Teams coordination
2. a project coordinator that should appear consistently across recurring meetings and collaboration spaces
3. an account-planning or research agent that needs licensed Microsoft 365 user-shaped access while still being governed as a nonhuman identity

The scaffold does not fake a fully live agent-user creation pipeline because that step deserves explicit enablement and testing. Instead, it models agent-user creation as a governed optional phase, which is the safer default.

## Where Work IQ Fits

Work IQ is the context and tool layer that makes the dispensed agent useful after it is governed. That is why each offer can declare the Work IQ MCP servers that make sense for the scenario.

For example:

1. `Work IQ Mail` and `Work IQ Calendar` fit triage, follow-up, and meeting coordination
2. `Work IQ Teams` fits persistent team collaboration and operational updates
3. `Work IQ User` fits participant context, reporting lines, and lightweight directory lookups
4. `Work IQ SharePoint` and `Work IQ OneDrive` fit document-grounded coordination and research

The important design point is that Work IQ does not replace identity governance. It amplifies a governed identity with context and deterministic tools. The vending machine is therefore not just provisioning an identity. It is provisioning a policy-bound execution context.

## Additional Prerequisites the Blog Should Not Skip

If you build this for real, you need more than just an HTTP trigger and a Graph token. At a minimum, the system needs:

1. Microsoft Agent 365 enabled through Frontier and at least one Microsoft 365 Copilot license in the tenant
2. a Function App with managed identity enabled
3. Microsoft Graph permissions and Entra roles suitable for bootstrap and runtime phases
4. a clear split between what is created once by platform administrators and what can be dispensed repeatedly by the runtime
5. entitlement management catalogs and access package policies prepared for the offers you want to sell
6. Conditional Access and logging on the vending machine itself, not just on the agents it creates
7. a storage location for the offer catalog and any resulting identifiers, whether file-backed, Key Vault-backed, or configuration-backed

Without that groundwork, the vending machine becomes a novelty dispenser instead of a governed provisioning service.

## Files Added in This Scaffold

The implementation scaffold added in this folder includes:

1. [project-agent-identities/FunctionApp/BootstrapOffering/run.ps1](c:/Repo/vsCode/project-agent-identities/FunctionApp/BootstrapOffering/run.ps1)
2. [project-agent-identities/FunctionApp/DispenseAgent/run.ps1](c:/Repo/vsCode/project-agent-identities/FunctionApp/DispenseAgent/run.ps1)
3. [project-agent-identities/FunctionApp/shared/AgentVendingMachine.psm1](c:/Repo/vsCode/project-agent-identities/FunctionApp/shared/AgentVendingMachine.psm1)
4. [project-agent-identities/FunctionApp/config/agent-offerings.sample.json](c:/Repo/vsCode/project-agent-identities/FunctionApp/config/agent-offerings.sample.json)
5. [project-agent-identities/FunctionApp/local.settings.sample.json](c:/Repo/vsCode/project-agent-identities/FunctionApp/local.settings.sample.json)

The code is deliberately a scaffold, not a claim of finished production automation. It is built to make the control points explicit:

1. what is catalog-driven
2. what is bootstrapped once
3. what is dispensed per request
4. what remains a deliberate human approval step

That is the right starting posture for preview-era agent automation.

## Closing Thought

If the first blog was about why agent identity governance matters, this continuation is about how to productize that governance. The agent vending machine is really an operating model disguised as an API. It says teams can move quickly, but only inside a catalog of known-safe patterns. It says an agent can be useful quickly, but not before it has a sponsor, a blueprint, a bounded permission model, and governed access. And it says the fastest way to scale agents is not to make provisioning looser. It is to make the good path radically easier than the bad one.

That is what a good vending machine does. It makes the right choice the easiest choice.

## References

[Overview of Microsoft Agent 365](https://learn.microsoft.com/en-us/microsoft-agent-365/overview).

[Create an agent identity blueprint](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/create-blueprint).

[Create agent identities in agent identity platform](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/create-delete-agent-identities).

[The agent's user account in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-users).

[Access packages for Agent identities](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/agent-access-packages).

[Authorization in Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-professional/authorization-agent-id).

[Work IQ MCP overview (preview)](https://learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview).
