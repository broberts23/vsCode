# Access Reviews Autopilot

Lab-shaped pipeline that takes Entra access-review questions to Slack for a decision, with Graph as the intended eventual edges. MyAccess remains the control plane; Slack is the inbox. There is no second human UI: Operators use API/CLI only.

## Language

**Review Work**:
One Approve/Deny question moving through the pipeline—from publish, through notification, to apply.
_Avoid_: Access review (as the message unit), work item, ticket

**Decision Item**:
The Graph address of a piece of Review Work: the principal×resource judgment under a review instance (definition, instance, decision item triple).
_Avoid_: Access review, review work (when you mean the Graph identifier)

**Access Review**:
The Entra product category and control-plane concept (definition/instance lifecycle in MyAccess)—not the pipeline message. This system stays on Access Reviews, not Access Packages.
_Avoid_: Access package, entitlement management assignment, using this as the name for a bus message

**Resource**:
The group, app, or other entitlement whose access for the Principal is under review.
_Avoid_: Target, asset, package (unless you literally mean an Access Package elsewhere)

**Correlation ID**:
The system-owned trace key for one piece of Review Work across bus, Slack, logs, and store. Not the Apply address.
_Avoid_: Decision item id, using the Graph triple as the Slack/button key

**Apply**:
Committing the Decider’s Approve/Deny choice to the system of record (Cosmos in the lab, Graph Decision Item in production). Graph Apply is delegated as the Reviewer only—application permissions cannot do it.
_Avoid_: Record (as a separate lab-only verb), sync, complete

**Decision**:
The Decider’s Approve or Deny choice for a piece of Review Work.
_Avoid_: Decision item, recommendation, approval (as a noun for the choice itself)

**Recommendation**:
The system-suggested Decision carried with Review Work. Always distinct from the Decision the Decider makes.
_Avoid_: Decision, default, hint (when you mean this field)

**Justification**:
Text that accompanies a Decision on Apply when the Access Review requires it. Distinct from Recommendation and from Decision. Lab may stub a constant; production collects it in the Inbox when required.
_Avoid_: Notes, comment, reason (when you mean this Graph-facing field)

**Review Event**:
An ingress signal that Review Work needs attention in the Inbox. In-scope kinds: Pending, Overdue, ReminderDue. Explains *why* we notified—not how far Apply has progressed. A later event for the same open Review Work refreshes it and may update/nudge the Inbox; Applied work is not reopened.
_Avoid_: Status, state, NotStarted (until a producer can emit it), access package event, notification (as the event name)

**Review Status**:
How far a piece of Review Work has progressed toward Apply: Received → Notified → Applied, or Failed when the worker path terminates without Apply after retries are exhausted (including poison/validation).
_Avoid_: Event, event type, pending (the old name for Received; also overloaded with Review Event Pending)

**Producer**:
The edge that emits Review Events into the pipeline. Lab: fixtures/simulator. Production: a Graph poller for Pending Decision Items, plus a scheduler that derives Overdue and ReminderDue. Not Access Package events; not Event Grid unless Graph later supports the resource.
_Avoid_: Event Grid (as the committed ingress), access package webhook

**Principal**:
The person or identity whose access is being reviewed.
_Avoid_: User, subject, account, reviewee

**Reviewer**:
The Entra-assigned person expected to decide the Review Work. Production intent: only the Reviewer may Apply; Inbox delivery targets the Reviewer.
_Avoid_: Approver, owner (unless you mean group owner outside this context)

**Decider**:
The person who actually clicked Approve or Deny in Slack. Distinct from Reviewer until identity mapping proves they are the same.
_Avoid_: Reviewer, actor, user

**Lab Identity Map**:
Lab-only bridge from Entra Reviewer to Slack Decider. Sandbox constraint: every Entra user resolves to the same Slack id. Not the production identity model.
_Avoid_: SSO, SSO Identity, directory sync (when you mean this lab stub)

**SSO Identity**:
Production end-state: Slack is SSO’d to Entra so Decider and Reviewer are the same person without a stub map. Not available in the Slack developer sandbox.
_Avoid_: Lab Identity Map, Linked Identity

**Operator**:
A person who injects Review Work through API or CLI and inspects via store or logs—never via a product UI, and never the party who decides access.
_Avoid_: Admin, user, reviewer, portal user

**Inbox**:
Slack—the only surface where Review Work is presented for a decision. Production shape: deliver to the Reviewer; a shared channel is lab scaffolding only.
_Avoid_: Portal, SPA, ops console, queue (when you mean the human decision surface)

**Control Plane**:
MyAccess / Entra—where review definitions and instances are governed. Out of process for this system today.
_Avoid_: Portal, inbox, ops console
