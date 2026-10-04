# 01: Record domain ADRs

**What to build:** Four short ADRs so the grilled decisions are on record: no product SPA/pending UI; Lab Identity Map vs SSO Identity; delegated Reviewer-only Graph Apply; production Producer = Graph poller + scheduler (not Event Grid/Access Packages).

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] ADR exists for removing the SPA and pending-queue UI (Slack-only Inbox; Operator API/CLI only)
- [ ] ADR exists for Lab Identity Map in the lab vs SSO Identity as production end-state
- [ ] ADR exists for Graph Apply being delegated and Reviewer-only (no application-permission Apply)
- [ ] ADR exists for production Producer = poller + scheduler, explicitly rejecting Access Package / unsupported Event Grid ingress
- [ ] ADRs use glossary vocabulary and live under the repo’s ADR convention
