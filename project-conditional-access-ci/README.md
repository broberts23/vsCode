# Conditional Access CI/CD Gatekeeper — enforce policies and automated policy tests

Summary
-------
Build a CI pipeline that validates Conditional Access posture for applications before deployment. Include policy-as-code templates, automated testing, drift detection, and remediation guidance. The repo demonstrates how to treat Conditional Access as part of your infrastructure pipeline rather than an afterthought.

Key Entra docs
-------------
- Conditional Access overview: https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview

Technologies
------------
- Policy-as-code stored in Git (JSON templates)
- GitHub Actions to run validation and call Graph reporting APIs
- PowerShell/Node.js scripts to validate policy JSON and check coverage
- Optional: integration with Microsoft Security Copilot/optimization agent (preview) for suggestions

Deliverables
------------
- `policies/` folder holding reusable CA policy templates
- `ci/` GitHub Actions workflows that lint, validate, and test policy changes
- `scripts/` tools to query CA coverage and risk signals via Graph
- `docs/` guidance on policy design and security tradeoffs

Implementation steps (expanded)
-------------------------------
1. Capture baseline Conditional Access templates
   - Create a small set of JSON templates for common policies (e.g., require MFA for admin roles, block legacy auth, require client app enforcement for sensitive apps).
   - Provide parameterization so policies can be reused across tenants/environments.

2. Create policy validation tools (scripts/)
   - Implement a validator that checks JSON schema, required fields, naming conventions, and safety checks (no overly broad exclusions, for example).
   - Implement a script to call Graph reporting endpoints that check current coverage for apps in the tenant and summarize gaps.

3. GitHub Actions gates (ci/)
   - On PRs that modify policies, run: JSON schema validation, policy linting, and a dry-run that simulates applying the policy to a non-production tenant (or calls the Graph API in a read-only mode to ensure no conflicts).
   - Add an optional manual approval step for production policy changes.

4. Drift detection and remediation
   - Implement a scheduled job that compares the Git baseline to the tenant's live policies and opens issues/PRs or creates alerts when drift is detected.

5. Integrate with sign-in simulation (optional)
   - Build a small harness that simulates sign-in attempts using different client types and signals to validate the effect of a policy before applying it.

6. Documentation and playbooks
   - Provide operator playbooks for rolling back a policy, testing changes safely, and onboarding new admins.

7. Tests and CI
   - Unit tests for the validator and integration tests that assert the scripts can fetch policy state and detect changes.

Demo / validation
-----------------
- Make a PR that weakens a policy; pipeline fails with guidance and a generated remediation PR. Schedule drift detection to run nightly and demonstrate it finding a change.

Estimated effort
----------------
- MVP: 4–8 days.

Why this fits your portfolio
---------------------------
This complements your security automation articles and shows a practical, code-first approach to identity policy governance.

Next steps
----------
- I can scaffold the `policies/`, `ci/`, and `scripts/` with starter templates and a GitHub Action that validates policy JSON.
