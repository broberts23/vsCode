# Workload Identity Security

## Baseline expectation

Workload identities should use the least privilege required, avoid long-lived credentials where possible, and prefer managed identity or federation over static secrets.

## Common risk indicators

- unused or stale service principals
- excessive application permissions
- certificates or secrets without clear rotation ownership
- automation identities shared across multiple unrelated workflows

## Analyst guidance

A reviewer should ask:

- does the workload identity still serve a real business process
- are the permissions broader than the workload requires
- is there an owner responsible for credential hygiene
- can the authentication path move to managed identity or federated credentials

## Copilot answer boundary

The assistant can summarize risks and recommended controls, but it should avoid implying a remediation was approved unless the grounded material shows approval evidence.
