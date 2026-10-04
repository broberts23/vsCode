# Lab Identity Map vs SSO Identity

Production intent is Reviewer-only Apply with Decider ≡ Reviewer via SSO Identity (Slack SSO’d to Entra). The Slack developer sandbox cannot do that SSO, so the lab uses a Lab Identity Map that resolves every Entra Reviewer to the same Slack id. The stub must not be mistaken for the production identity model.
