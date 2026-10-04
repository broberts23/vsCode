# 05: Review Work lifecycle integrity

**What to build:** Republishing Review Work for an open Correlation ID upserts/refreshes without duplicating work. Overdue/ReminderDue update or nudge the existing Inbox card while status is Notified. Applied work never reopens. Terminal worker failures after retries (including poison/validation) land in Failed.

**Blocked by:** 03 (Align Review Status and Review Events)

**Status:** ready-for-agent

- [ ] Idempotent upsert for open Review Work (same Correlation ID) refreshes metadata without creating duplicates
- [ ] Overdue/ReminderDue while Notified updates/nudges the existing Inbox card (no stack of orphan cards required)
- [ ] Review Events against Applied work do not reopen or re-Inbox the decision
- [ ] Failed is set when notify/apply/validation terminates after retries are exhausted (including poison)
- [ ] Poison fixtures remain opt-in on simulate
- [ ] Domain/worker behavior tests cover idempotency, no-reopen, nudge-while-open, and Failed
