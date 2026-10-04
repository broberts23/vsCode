# 06: Align narrative docs to glossary

**What to build:** Blog, README, Entra/Slack docs, and related narrative match the glossary: Slack-only Inbox, no SPA/pending queue, Received/Failed language, Lab Identity Map vs SSO Identity, delegated Apply, poller+scheduler Producer intent. Access Package / unsupported Event Grid ingress stories are gone.

**Blocked by:** 02 (Remove second inbox), 03 (Align Review Status and Review Events), 04 (Lab Apply contract), 05 (Review Work lifecycle integrity)

**Status:** ready-for-agent

- [ ] Blog diagrams and prose no longer describe SPA or pending-queue API as product surfaces
- [ ] Blog/README lifecycle language uses Received (not status `pending`) and matches Failed/idempotency behavior
- [ ] Entra and Slack docs no longer treat the SPA as a required surface; Operator API auth remains clear
- [ ] Docs call out Lab Identity Map (lab) vs SSO Identity (production) and shared channel as lab scaffolding
- [ ] Docs/stub narrative for production Producer is poller + scheduler; Access Package Event Grid slip is removed
- [ ] Glossary vocabulary is used consistently; no new synonym drift introduced
