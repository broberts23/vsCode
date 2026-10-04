# Delegated Reviewer-only Graph Apply

Graph Decision Item PATCH supports delegated `AccessReview.ReadWrite.All` only; application permissions are not supported, and the caller must be a listed Reviewer. We will not Apply via managed identity or app-only `AccessReview.ReadWrite.All`. Lab Apply stays simulated in Cosmos; a future Graph applier must act as the Reviewer (after Lab Identity Map or SSO Identity resolves the Decider).
