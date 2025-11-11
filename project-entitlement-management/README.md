# Entitlement Management for Project Onboarding — automated access packages + lifecycle

Summary
-------
Build an entitlement-management-driven onboarding system so project teams and external partners can self-request access packages that grant time-limited group/app access with automated provisioning and cleanup. This project shows how to model access as access packages, create policies for approval/expiration, and automate lifecycle actions with Microsoft Graph.

Key Entra docs
-------------
- Entitlement management overview: https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview
- Entitlement Management Graph tutorial: https://learn.microsoft.com/en-us/graph/tutorial-access-package-api?toc=/azure/active-directory/governance/toc.json

Technologies
------------
- Microsoft Graph (Access Package APIs)
- Bicep for infra and sample resources
- PowerShell (Graph PowerShell) or a small Node.js backend for orchestrations
- GitHub Actions for CI and scheduled access reviews
- Azure AD B2B flows for external user onboarding

Deliverables
------------
- `infra/` Bicep templates to create sample catalog, groups and protected app
- `scripts/` scripts to create access packages, policies and to simulate requests
- `ci/` workflows to run periodic access reviews and lifecycle automation
- `docs/` README with step-by-step onboarding instructions and license considerations

Implementation steps (expanded)
-------------------------------
1. Map the onboarding scenarios
   - Define two or three practical onboarding scenarios: internal dev access, external partner contributor, and short-term contractor.
   - For each scenario, enumerate required resources (groups, app roles, SharePoint sites) and the approval & expiration rules.

2. Deploy sample resources (infra/)
   - Use Bicep to provision a catalog owner, example groups, and a demo enterprise app with a test role. Output IDs for automation.

3. Access package creation scripts (scripts/)
   - Implement PowerShell scripts to programmatically create catalogs, access packages, and policies using Microsoft Graph.
   - Provide a `create-access-package.ps1` script that accepts a JSON definition and returns the packageId and policyId.

4. Simulate requests and approvals
   - Simulate B2B onboarding: script invites an external test user, then creates an access request for that user and demonstrates the approval workflow.
   - Show how delegated access package managers can approve requests without tenant-admin rights.

5. Automation for lifecycle and reviews
   - Implement scheduled GitHub Actions that trigger lifecycle workflows or call the access review API to create sample reviews and send reminders.
   - Provide scripts to export access assignments and detect stale access.

6. Self-service portal
   - Build a lightweight static site or single-page app that lists available access packages and opens the request dialog (or links to the built-in Entra request flow). Backend for protected actions can be Azure Functions.

7. Cleanup and retention
   - Implement automatic cleanup: when access packages expire and a guest has no remaining assignments, remove their B2B account for tidy tenant hygiene.

8. Tests and CI
   - Add unit tests for the scripts and integration tests that create and clean up packages in a test tenant or isolated subscription.

Demo / validation
-----------------
- Three end-to-end scenarios demonstrate request, approval, assignment, review, extension, and cleanup. Each scenario lists resources in the access package, policy settings, and expected outcomes.

### Scenario 1 — Internal developer access (employee)
- Resources in the access package
   - Group: Dev Team security group (Member role) for app/resource gating.
   - Application: Internal Web API app role "Developer" (if app roles are defined) for RBAC inside the app.
   - SharePoint: Project site (Contributor role) for documentation and design docs.
   - Microsoft Entra role (Preview): Directory Readers as an Active Member if needed for non-privileged directory read scenarios, or a privileged role as Eligible only. See “Add a Microsoft Entra role assignment” (Preview) guidance: https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-resources#add-a-microsoft-entra-role-assignment
- Request policy
   - Who can request: All employees in specific departments (e.g., Engineering) or specific users/groups.
   - Approval: Auto-approve or single-stage manager approval depending on risk.
   - Assignment duration: 90 days default.
   - Extensions: Requestor can submit an extension request with justification 14 days before expiry; requires manager approval.
- Governance
   - Access reviews: Monthly recurring access review of access package assignments by the Dev Team resource owner. Reviewers make keep/remove decisions; auto-apply results. Access reviews overview: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview
   - Expiration: If not extended or renewed, assignment expires and group/app/site memberships are removed. If the user has no other access package assignments, nothing else happens (internal user retained).
- Success criteria
   - Internal user self-requests, gains access within minutes, can call the Web API with Developer role and access the SharePoint site, and appears in the Dev Team group. Review and extension flows behave as configured.

### Scenario 2 — External partner contributor (guest B2B)
- Resources in the access package
   - Group: Partner Project security group (Member role) used for application authorization and SharePoint access.
   - Application: SaaS or enterprise app role "Contributor" assigned to the user (or to the group if the app is group-assigned).
   - SharePoint: External collaboration site (Read or Contribute role).
   - Note: Avoid assigning privileged Microsoft Entra directory roles to guests via this package; prefer app roles and group-scoped access.
- Request policy
   - Who can request: Users from selected connected organizations; users not yet in the directory may be auto-invited when approved.
   - Approval: Two-stage approval — project sponsor then security reviewer for external access.
   - Assignment duration: 30 days default, max 90; can request extension once with justification.
- Governance
   - Access reviews: Bi-weekly review scoped to guests in this access package; reviewers are project owners. Denied or non-responded assignments are auto-removed. Where do you create reviews and cadence guidance: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview#where-do-you-create-reviews
   - Cleanup: When the guest’s last assignment expires and they have no other access packages, automatically remove the B2B account for tenant hygiene. Entitlement management overview: https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview
- Success criteria
   - Guest self-requests via the portal, invitation is issued upon approval, access is granted to the app and SharePoint site, periodic reviews prompt owners, and on expiry with no extension the guest account is removed.

### Scenario 3 — Short‑term contractor with eligible Entra role (Preview)
- Resources in the access package
   - Group: Contractor Project group (Member role) to gate application features.
   - Application: Enterprise or line-of-business app role "Operator".
   - Microsoft Entra role (Preview): e.g., User Administrator or other required role set as Eligible Member so the user must activate via PIM with MFA/justification/time limit. For privileged roles, only Eligible is allowed. Learn more: https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-resources#add-a-microsoft-entra-role-assignment
- Request policy
   - Who can request: Specific directory users tagged as contractors (dynamic group or curated list).
   - Approval: Two-stage approval — engagement manager then identity governance admin (or delegated approver).
   - Assignment duration: 14–30 days; cannot exceed PIM or role policy constraints.
   - Extensions: Allowed once with strong justification; requires both approvers.
- Governance
   - Access reviews: Weekly review of package assignments; reviewers are engagement managers. Non-response results in removal.
   - PIM activation: Eligible Entra role must be activated in Microsoft Entra PIM per session; logs and alerts enforced by PIM policy.
- Success criteria
   - Contractor gains group and app role access immediately; Entra role requires explicit PIM activation when needed. Reviews and short expirations keep access tight; lack of extension removes access.

References for API and automation
- Tutorial using Graph entitlement management APIs: https://learn.microsoft.com/en-us/graph/tutorial-access-package-api?toc=/azure/active-directory/governance/toc.json
- Change and add resource roles (includes Entra role assignment Preview): https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-resources
- Access reviews overview and guidance: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview

Portal concept (self-service)
----------------------------
The portal is a lightweight UI that advertises access packages and routes users into the official Microsoft “My Access” request flow, with optional backend automation for inventory, reviews, and reporting.

- Information architecture
   - Home: Cards for access packages with title, short description, resources (groups/apps/sites/Entra roles), default duration, who can request, and approval type.
   - Package details: Full resource list and roles, request policy, review cadence, and links: “Request access” and “Open in My Access”.
   - My requests: Status of pending/approved/expired requests with actions to extend or cancel.
   - Approver view: Queue of incoming requests with justification, resource summary, and approve/deny controls. Links to Microsoft Entra admin center for deep management.
   - Admin view: Inventory of packages, assignment counts, upcoming expirations, review schedules, and export to CSV.

- UX notes
   - Clearly label Entra role assignments as Preview, and whether the role is Active or Eligible. For privileged roles show an informational banner: “Eligible only — activate in PIM to use.”
   - For guests, show the connected organization and the fact that an invitation will be sent after approval.
   - For extension windows, show “Extend” starting N days before expiry and explain required approval(s).

- Technical sketch
   - Frontend: Static SPA (e.g., Azure Static Web Apps) or static site listing packages from a curated JSON or backend API.
   - Backend: Azure Functions (managed identity) or small API to call Microsoft Graph entitlement management endpoints for inventory, assignment exports, and optional request simulations. Use least-privilege delegated or application permissions and store secrets in Key Vault.
   - Requests: Prefer deep-linking to the official My Access portal for the actual request/approval workflow to avoid duplicating Microsoft’s UX and logic.
   - Automation: Scheduled job to create access reviews for packages with guests and to export assignment snapshots for audit. See access reviews overview: https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview

- Governance wiring in the portal/workflows
   - Access reviews per package: allow selecting reviewers (resource owners, managers, self-review), frequency (weekly/monthly/quarterly), auto-apply decisions, and remediation behavior.
   - Extension policy: define extension window and approvers; require justification and optionally re-attestation of business need.
   - Cleanup: When an assignment expires and no other package remains, trigger guest removal. Behavior aligns with entitlement management built-in cleanup. Overview: https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview

Security and role-assignment notes (Preview)
-------------------------------------------
- Adding Microsoft Entra directory roles to access packages is in Preview. Only Global Administrator or Privileged Role Administrator with Catalog Owner permissions can add Entra roles to a catalog; once present, access package managers can include them. Details: https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-access-package-resources#add-a-microsoft-entra-role-assignment
- For privileged roles, only Eligible membership is permitted. Users must activate via PIM with MFA/justification and time-bound settings. Consider using PIM for groups where appropriate.
- Prefer assigning app roles and group memberships over directory roles. Use directory roles only when required and keep them eligible with tight PIM policies.

What you will see in the demo
- A tenant with three access packages aligned to the scenarios above.
- Self-service request by employee and guest, approvals routed, and assignments granted to group/app/site (and Entra role eligibility where configured).
- Access reviews running on the configured cadence; reviewers approve/deny. Denies auto-remove access. Lack of response follows configured default outcome.
- Extension requests permitted within the window and requiring justification/approval per package policy.
- On expiry: internal users lose resource access; external users without other assignments are removed from the tenant automatically.

Estimated effort
----------------
- MVP: 4–7 days. Full portal and tight integration: 2–3 weeks.

Why this fits your portfolio
---------------------------
This project ties Bicep and automated scripting to a real-world governance story about collaboration with partners — a nice complement to your existing Azure automation content.

Next steps
----------
- I can scaffold `infra/`, `scripts/`, and a sample GitHub Action that creates an access package and simulates a request.
