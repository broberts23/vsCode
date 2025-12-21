# Policy & allowlists

The policy file lives at `src/FunctionApp/policy/policy.json` and is loaded by the Function.

## Goals

- Keep remediation safe-by-default
- Make changes auditable and reviewable (policy-as-code)
- Restrict automation to explicit allowlists

## Key fields

- `mode`: `detect` or `remediate`
- `breakGlass`: principals that are never modified
- `allowLists`: the only groups/apps/roles the automation may change
- `rules[]`: match conditions and action steps

## Recommended rollout

1) Start with `mode: detect`
2) Observe events and confirm matching behavior
3) Populate allowlists
4) Enable remediation per-rule (or globally) in a controlled environment
