# Delegated Reviewer-only Graph Apply

Graph Decision Item PATCH supports delegated `AccessReview.ReadWrite.All` only; application permissions are not supported, and the caller must be a listed Reviewer. We will not Apply via managed identity or app-only `AccessReview.ReadWrite.All`. Lab Apply stays simulated in Cosmos; production Graph Apply must use a delegated token for the Reviewer (via SSO Identity so Decider ≡ Reviewer)—the Lab Identity Map only bridges Reviewer to Slack for delivery and does not authorize Apply.
