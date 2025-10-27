# Identity Governance Dashboard & Automation — Graph-driven access reviews, lifecycle workflows

Summary
-------
Build a dashboard that aggregates identity governance signals (access reviews, lifecycle workflows, entitlement metrics) and provides one-click remediation or re-certification actions driven by Microsoft Graph APIs. The project demonstrates building an operational plane for identity governance with automation hooks.

Key Entra docs
-------------
- Identity Governance overview (Graph): https://learn.microsoft.com/en-us/graph/api/resources/identitygovernance-overview?view=graph-rest-1.0
- Access reviews API: https://learn.microsoft.com/en-us/graph/api/resources/accessreviewsv2-overview?view=graph-rest-1.0
- Lifecycle Workflows APIs: https://learn.microsoft.com/en-us/graph/api/resources/identitygovernance-lifecycleworkflows-overview?view=graph-rest-1.0

Technologies
------------
- React (or static site) for the dashboard
- Azure Functions for backend Graph proxy
- Bicep for infra
- GitHub Actions for CI and scheduled jobs

Deliverables
------------
- `src/` frontend and `api/` backend code to call Graph
- `infra/` Bicep for Function App, storage, and App Registration
- `ci/` pipeline to deploy the dashboard and run synthetic tests
- `docs/` README with required Graph permissions and security guidance

Implementation steps (expanded)
-------------------------------
1. Define KPIs and UX
   - Decide the key governance artifacts to display: pending access reviews, failing attestations, expired access packages, PIM activations, and lifecycle workflow failures.
   - Sketch simple views: overview, per-resource access details, and actions panel.

2. App registration & permissions
   - List the exact Microsoft Graph permissions needed (least-privilege): AccessReviews.Read.All, IdentityLifecycle.ReadWrite.All (or similar) and document admin consent steps. Provide a consent checklist in the README.

3. Backend endpoints (api/)
   - Implement Azure Function endpoints that call Graph and return consolidated objects. Provide both delegated and application-auth examples for local dev vs deployed run.
   - Implement caching and paging so the dashboard is responsive and avoids hitting tenant rate limits.

4. Frontend (src/)
   - Build a minimal dashboard showing cards and lists. Include quick actions: trigger an access review, re-send a reminder, or launch a re-certification flow.
   - Make operations require confirmation and display returned Graph operation results as structured JSON with human-friendly summaries.

5. Automation actions
   - Add automation endpoints for typical actions: auto-revoke expired assignments, schedule lifecycle workflows, or escalate pending approvals.

6. Security considerations
   - Use Managed Identity for the Function App when deployed, and store any required secrets in Key Vault. Document the required RBAC and Graph roles.

7. Tests and CI
   - Add unit tests for API wrappers and e2e tests that mock Graph to simulate the governance scenarios. Use TestDrive or local mock frameworks for isolation.

Demo / validation
-----------------
- Deploy the dashboard to a test subscription, run an access review flow and show the dashboard updating in near-real time; demonstrate triggering a remediation action.

Estimated effort
----------------
- MVP: 1–2 weeks.

Why this fits your portfolio
---------------------------
This brings together your automation and Azure skills and produces a visually compelling artifact to show identity governance in practice.

Next steps
----------
- I can scaffold the `src/`, `api/`, `infra/`, and `ci/` folders with starter templates and a sample Azure Function that calls Graph (read-only) and returns a small set of governance metrics.
