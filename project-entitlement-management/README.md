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
   - Implement scripts to programmatically create catalogs, access packages, and policies using Microsoft Graph. Include both PowerShell and Node.js examples where appropriate.
   - Provide a `create-access-package.ps1` script that accepts a JSON definition and returns the packageId and policyId.

4. Simulate requests and approvals
   - Simulate B2B onboarding: script invites an external test user, then creates an access request for that user and demonstrates the approval workflow.
   - Show how delegated access package managers can approve requests without tenant-admin rights.

5. Automation for lifecycle and reviews
   - Implement scheduled GitHub Actions that trigger lifecycle workflows or call the access review API to create sample reviews and send reminders.
   - Provide scripts to export access assignments and detect stale access.

6. Self-service portal (optional)
   - Build a lightweight static site or single-page app that lists available access packages and opens the request dialog (or links to the built-in Entra request flow). Backend for protected actions can be Azure Functions.

7. Cleanup and retention
   - Implement automatic cleanup: when access packages expire and a guest has no remaining assignments, remove their B2B account for tidy tenant hygiene.

8. Tests and CI
   - Add unit tests for the scripts and integration tests that create and clean up packages in a test tenant or isolated subscription.

Demo / validation
-----------------
- Create three scenarios and run them end-to-end: request access as internal user, request as guest user, run scheduled access review that revokes expired assignments.

Estimated effort
----------------
- MVP: 4–7 days. Full portal and tight integration: 2–3 weeks.

Why this fits your portfolio
---------------------------
This project ties Bicep and automated scripting to a real-world governance story about collaboration with partners — a nice complement to your existing Azure automation content.

Next steps
----------
- I can scaffold `infra/`, `scripts/`, and a sample GitHub Action that creates an access package and simulates a request.
