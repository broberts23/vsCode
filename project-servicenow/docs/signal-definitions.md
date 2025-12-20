# Signal definitions (initial scope)

This project starts with three signal categories. The intent is to keep the definitions **explicit and testable**, so the automation is predictable.

## 1) Privileged drift

**Goal:** detect privileged assignment changes that are unexpected or require review.

**Typical sources:**

- Microsoft Graph role management data (directory role assignments / privileged role schedules)
- Audit events that indicate privileged assignments changed

**Default detection rule (suggested):**

- A privileged role assignment is **new** since the last run, OR
- A privileged role assignment is **modified** (scope/duration/principal changed) since the last run

**ServiceNow outcome:**

- Create/update a task containing:
  - principal (user/SP), role name, scope, detected timestamp
  - recommended remediation steps
  - links to Entra portal / Graph resource

## 2) Access reviews status

**Goal:** ensure access reviews are started and completed on time.

**Typical sources:**

- Microsoft Graph Access Reviews APIs

**Default detection rule (suggested):**

- A review is **not started** within a configured window, OR
- A review is **overdue** (end date passed and not completed), OR
- (Optional) decisions include “Remove” and you want a downstream verification task

**ServiceNow outcome:**

- Create/update a task assigned to the reviewer group or app owner group.
- Set `due_date` to the review end date (or earlier, based on policy).

## 3) Orphaned privileged assignments

**Goal:** find privileged assignments that should not exist because the principal is no longer valid or should not hold privilege.

**Suggested definition (pick one and document it):**

- **Strict orphan:** assignment principal no longer exists (deleted) OR cannot be resolved.
- **Disabled orphan:** assignment principal exists but is disabled.
- **Policy orphan:** principal is enabled but violates policy (e.g., no longer in eligible population).

**Default detection rule (suggested):**

- Any privileged assignment where the principal is deleted/disabled.

**ServiceNow outcome:**

- Create/update a task with higher priority for critical roles.

## Cross-cutting behavior

- **Idempotent upsert:** do not create duplicates; correlate by `(source_type, source_id)`.
- **Close conditions:** only auto-close when the signal is clearly remediated (e.g., assignment removed; review completed).
