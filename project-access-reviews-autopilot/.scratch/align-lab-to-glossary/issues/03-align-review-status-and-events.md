# 03: Align Review Status and Review Events

**What to build:** New Review Work is stored as **Received** (not `pending`) so status language no longer collides with Review Event Pending. **NotStarted** is removed from the supported Review Event surface until a Producer can emit it. Lifecycle language in models/tests matches the glossary.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Review Status enum/document lifecycle uses Received → Notified → Applied | Failed (no `pending` status value)
- [ ] Creating Review Work from a Review Event yields status Received
- [ ] Review Event kinds on the supported surface are Pending, Overdue, ReminderDue only
- [ ] NotStarted is not part of the supported domain surface
- [ ] Unit/domain tests cover Received on create and the supported event set
- [ ] Code and test strings that described status `pending` are updated (blog-wide narrative can wait for ticket 06)
