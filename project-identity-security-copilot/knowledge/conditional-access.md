# Conditional Access for Privileged Access

## Baseline expectation

Privileged admin workflows should require phishing-resistant MFA, named locations where appropriate, device or session controls where justified, and clear exception handling.

## Common weak pattern

A broad policy that protects standard users but excludes emergency accounts, automation principals, and legacy admin paths without compensating controls creates a review gap.

## Analyst guidance

When reviewing a privileged access path, verify:

- whether the account is human or workload-based
- whether MFA strength is appropriate for the privilege level
- whether exclusions are documented and time-bound
- whether break-glass accounts are monitored and tightly limited

## Copilot answer boundary

The assistant should recommend control patterns, but it should not claim a tenant is compliant unless grounded evidence is present.
