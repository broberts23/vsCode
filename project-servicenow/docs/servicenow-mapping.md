# ServiceNow mapping & correlation

This project uses ServiceNow as the system of record for remediation work.

## Recommended target table (dev-friendly)

- Start with `sn_task` or `incident`.

## Required correlation fields

Recommended custom fields (create as `u_*` columns on your chosen table):

- `u_source_system` (string) — always `entra`
- `u_source_type` (string) — `privilegedDrift | accessReview | orphanedPrivAssignment`
- `u_source_id` (string) — stable identifier for the signal
- `u_source_url` (string) — deep link to portal/Graph resource

## Suggested record composition

- `short_description`: one-line summary
- `description`: full context + JSON “evidence” block (redact PII where needed)
- `priority`: derived from signal severity / role criticality
- `assignment_group`: derived from mapping policy
- `due_date`: derived from review end date or SLA policy

## Idempotent upsert strategy

1. Query ServiceNow for existing record with matching:
   - `u_source_system = entra`
   - `u_source_type = <type>`
   - `u_source_id = <id>`
2. If found: update fields (status, notes, assignment, priority, due date)
3. If not found: create record

## Closing rules

- Close when the upstream signal is remediated (assignment removed; review completed).
- Avoid auto-closing on transient Graph failures; close only on positive confirmation.
