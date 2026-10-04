Status: resolved

# Align lab to domain glossary

## Problem Statement

The lab pipeline works, but its product surface and vocabulary disagree with the domain model we just locked. A SPA and pending-queue API imply a second inbox; Review Status still says `pending` and collides with Review Event Pending; Failed is decorative; there is no Lab Identity Map or Justification on Apply; and docs still sell dual UI and sometimes contradict Graph Apply authorization. Operators and future agents cannot trust the code or the blog as a map of what this system is.

## Solution

Align the lab to `GLOSSARY.md`: Slack is the only Inbox; Operators inject via API/CLI only; Review Status is Received → Notified → Applied | Failed; Apply stays one concept with a lab Justification stub and Lab Identity Map; idempotent Review Event handling matches the glossary; docs and stub comments tell the same story. Production poller, SSO Identity, and Reviewer-targeted delivery remain documented intent—not built in this change.

## User Stories

1. As an Operator, I want to inject Review Work through the simulate API only, so that I do not depend on a product UI.
2. As an Operator, I want to inject Review Work through the simulator CLI/job, so that demos and cron still work without a SPA.
3. As an Operator, I want the SPA removed, so that nobody mistakes a local test GUI for a product surface.
4. As an Operator, I want `GET /api/pending` removed, so that there is no headless second inbox.
5. As an Operator, I want Entra OIDC to protect simulate (and any remaining Operator API), so that injection stays authenticated.
6. As an Operator, I want to inspect open Review Work via Cosmos or logs, so that I can debug without a pending queue UI.
7. As a Decider, I want Approve/Deny only in Slack, so that the Inbox is unambiguous.
8. As a Decider, I want the Slack card to show Principal, Resource, due date, Recommendation, and Correlation ID, so that I can decide in place.
9. As a Decider, I want Overdue and ReminderDue to update or nudge the existing Inbox card while Review Work is still open, so that time-based events actually chase me.
10. As a Decider, I want Applied Review Work not to reopen when fixtures are replayed, so that I am not asked to decide twice.
11. As a Decider, I want the card to update after Apply, so that I see the outcome where I clicked.
12. As a Reviewer, I want production intent documented that only I may Apply, so that the lab does not pretend app-only Graph Apply is valid.
13. As a Reviewer, I want production intent documented that Inbox delivery targets me, so that a shared channel is clearly lab scaffolding.
14. As a Principal, I want my access decision recorded against the correct Decision Item address, so that Apply can target Graph later without remapping.
15. As an Operator, I want Review Status to use Received instead of pending, so that status language does not collide with Review Event Pending.
16. As an Operator, I want status transitions Received → Notified → Applied to remain visible on the correlation document, so that traceability matches the glossary.
17. As an Operator, I want Failed to be set when notify/apply/validation terminates after retries (including poison), so that Failed is a real terminal state.
18. As an Operator, I want poison fixtures to still be opt-in on simulate, so that bad messages do not appear in normal runs.
19. As an Operator, I want republishing the same open Review Work to upsert/refresh metadata without duplicating work, so that demos can replay safely.
20. As an Operator, I want Applied documents to ignore reopen attempts, so that Correlation ID remains one finished piece of Review Work.
21. As a Decider, I want Apply to carry a lab-stub Justification, so that the Apply contract includes the Graph-facing field before live Apply exists.
22. As a future Graph applier, I want Justification distinct from Recommendation and Decision in the model, so that overrides and audit text stay separate.
23. As a Decider, I want Lab Identity Map to resolve every Entra Reviewer to the same Slack id in the lab, so that sandbox constraints are explicit and testable.
24. As a future production owner, I want SSO Identity called out as the end-state (not Lab Identity Map), so that nobody ships the stub map to production by mistake.
25. As an Operator, I want Review Events limited to Pending, Overdue, and ReminderDue, so that unused NotStarted language does not linger in the domain surface.
26. As an Operator, I want Recommendation to remain on Review Work and cards, so that overrides against system suggestion stay visible.
27. As a reader of the blog, I want diagrams and prose without the SPA/pending queue story, so that the narrative matches the product.
28. As a reader of the README, I want layout and demo steps without serving `spa/`, so that local setup matches reality.
29. As a reader of Entra/Slack docs, I want SPA app-registration guidance removed or relegated, so that Operator API auth is the only Entra UI story.
30. As an implementer, I want `GraphAccessReviewClient` docs to say delegated Reviewer-only Apply, so that they do not contradict the glossary and Entra guidance.
31. As an implementer, I want ADRs for no SPA, Lab Identity Map vs SSO Identity, delegated Apply, and poller+scheduler Producer, so that surprising decisions survive the next agent.
32. As an implementer, I want glossary vocabulary used in new code and docs, so that synonyms do not creep back.
33. As a tester, I want behavioral tests at the HTTP API and shared domain-contract seam, so that alignment is enforced without testing Cosmos/Slack internals.
34. As an Operator, I want health checks unchanged, so that platform probes do not depend on the removed pending API.
35. As a Decider, I want Slack signature verification unchanged, so that interactivity stays safe while surfaces are deleted.
36. As an Operator, I want infra env vars for SPA client id removed or unused when the SPA dies, so that deploy config does not advertise a ghost UI.
37. As a future Producer author, I want fixtures to remain Graph-shaped with the Decision Item triple, so that a Graph poller can replace the simulator without message redesign.
38. As a future Producer author, I want Overdue/ReminderDue documented as scheduler-derived in production, so that push-only ingress is not assumed.
39. As an auditor, I want Decision, Recommendation, Decider, and timestamps preserved on Applied documents, so that overrides remain explainable.
40. As an Operator, I want 30-day TTL to remain lab cleanup only, so that nobody treats it as compliance retention.
41. As an implementer, I want Access Packages explicitly out of vocabulary in docs that might confuse ingress, so that the access-package slip does not return.
42. As a Decider, I want shared-channel delivery to keep working in the lab after alignment, so that demos still function before Reviewer-targeted delivery exists.

## Implementation Decisions

- Single test seam: HTTP API + shared domain contracts (`ara` models/store/apply message behavior). No new seams.
- Remove the SPA static app and all demo/docs paths that serve or configure it as a product surface.
- Remove the pending-list API endpoint and any store helpers that exist only to feed that UI.
- Keep Operator injection: simulate API (OIDC-protected) and simulator CLI/job.
- Rename Review Status `pending` → `Received` everywhere in models, store writes, tests, and docs that describe lifecycle (Review Event `ReviewPending` stays an event name).
- Keep Review Status `Notified`, `Applied`; make `Failed` reachable for terminal worker failures after retries exhausted (including poison/validation paths)—document the exact trigger points in code comments only where behavior is non-obvious.
- Remove or stop exposing `ReviewNotStarted` on the domain surface until a Producer emits it.
- Apply path: add Justification to the Apply contract; lab fills a constant stub; do not build Slack modals in this change.
- Introduce Lab Identity Map as an explicit lab construct: every Entra Reviewer resolves to the same configured Slack id; record Decider from Slack as today; document that production uses SSO Identity instead.
- Idempotent Review Event handling: upsert by Correlation ID for open work; refresh metadata; for Overdue/ReminderDue while Notified, update/nudge the existing Inbox card; never reopen Applied.
- Shared Slack channel remains lab delivery; do not implement Reviewer DMs in this change—document as scaffolding.
- Fix stub/docs contradiction: Graph Apply is delegated, Reviewer-only; no application permission path; do not grant `AccessReview.ReadWrite.All` on MI for Apply.
- Update blog, README, Entra app registration docs, and Slack docs to remove second-inbox language and align with glossary terms (Inbox, Control Plane, Review Work, Operator, etc.).
- Add ADRs under `docs/adr/`:
  1. No product SPA / no pending UI
  2. Lab Identity Map vs SSO Identity
  3. Delegated Reviewer-only Graph Apply
  4. Production Producer = Graph poller + scheduler (not Event Grid/Access Packages)
- Preserve Service Bus dual-subscription shape (notify / apply); this change does not redesign messaging topology.
- Cosmos TTL stays 30 days as lab cleanup; no production retention policy claim.
- Simulated Apply remains Cosmos + card update; live Graph Apply stays out of scope.

## Testing Decisions

- Good tests assert external behavior only: HTTP responses, domain model validation, status transitions, idempotency rules, Apply payload fields (Justification), and Lab Identity Map resolution—not Cosmos SDK calls, Slack HTTP, or Bicep.
- Primary modules under test: API routes that remain after SPA/pending removal; domain models/enums; correlation/Apply message contracts; identity map helper; fixture loading/event kinds; worker-facing validation (poison → failure path).
- Prefer extending the existing unit-test style (pure functions, model round-trips, signature helpers) over new integration harnesses.
- Where API behavior is tested, use the in-process HTTP test client against the app with auth bypass or injected auth—do not require deployed Container Apps.
- Do not require live Slack, Graph, or Event Grid in CI.
- Cover at least: Received status on create; no pending-list route; simulate still publishes; Applied not reopened; Justification present on Apply message/document path; Lab Identity Map constant resolution; ReviewNotStarted absent from supported events; Failed (or equivalent terminal behavior) for poison after worker validation.

## Out of Scope

- Implementing production Graph poller or overdue/reminder scheduler
- Live Graph Decision Item PATCH / OBO token flow
- Enforcing Reviewer-only Apply in the lab (beyond documenting intent and Lab Identity Map)
- Reviewer-targeted Slack DMs / per-reviewer channels
- Slack Enterprise SSO / SSO Identity implementation
- Event Grid partner topics or Access Package events
- SPA Approve/Deny (SPA is deleted, not extended)
- Changing Service Bus topic/subscription topology
- Production retention/compliance policy beyond acknowledging lab TTL
- Collecting Justification via Slack modal (stub only)
- Easy Auth, Functions, or other explicitly rejected platform pieces

## Further Notes

- Glossary at repo root is source of vocabulary; do not invent synonyms in the implementation.
- Blog currently describes SPA + `GET /api/pending` and status `pending`; those sections must be rewritten, not lightly edited.
- Infra still carries SPA client id configuration; remove or stop requiring it when the SPA is gone, without breaking unrelated Container Apps settings.
- This spec is alignment of the lab to the grilled domain model, not the production edge build. ADRs should record production intent so later specs can attach there cleanly.
