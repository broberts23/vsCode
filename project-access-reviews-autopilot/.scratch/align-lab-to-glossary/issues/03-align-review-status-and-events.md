# 03: Align Review Status and Review Events

**What to build:** New Review Work is stored as **Received** (not `pending`) so status language no longer collides with Review Event Pending. **NotStarted** is removed from the supported Review Event surface until a Producer can emit it. Lifecycle language in models/tests matches the glossary.

**Blocked by:** None (can start immediately).

**Status:** resolved

- [x] Review Status enum/document lifecycle uses Received → Notified → Applied | Failed (no `pending` status value)
- [x] Creating Review Work from a Review Event yields status Received
- [x] Review Event kinds on the supported surface are Pending, Overdue, ReminderDue only
- [x] NotStarted is not part of the supported domain surface
- [x] Unit/domain tests cover Received on create and the supported event set
- [x] Code and test strings that described status `pending` are updated (blog-wide narrative can wait for ticket 06)

## Answer

`ReviewStatus.RECEIVED` (`received`) replaces `pending`; `ReviewNotStarted` removed from `ReviewEventType`. Domain tests in `tests/test_review_status_and_events.py`. Blog lifecycle wording deferred to ticket 06.
