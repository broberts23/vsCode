# 04: Lab Apply contract (Justification + Lab Identity Map)

**What to build:** Apply carries a lab-stub **Justification** distinct from Recommendation and Decision. A **Lab Identity Map** resolves every Entra Reviewer to the same configured Slack id. Graph Apply stub documentation matches delegated Reviewer-only Apply. SSO Identity remains documented production end-state, not implemented.

**Blocked by:** None (can start immediately).

**Status:** resolved

- [x] Apply message/document path includes Justification; lab fills a constant stub (no Slack modal)
- [x] Justification is distinct from Recommendation and Decision in the model
- [x] Lab Identity Map resolves any Entra Reviewer to the same Slack id (configurable)
- [x] Graph Apply stub/docs state delegated Reviewer-only Apply; no MI application-permission Apply story
- [x] Tests cover Justification on Apply and Lab Identity Map resolution at the domain/API seam

## Answer

Added `justification` on Apply/document paths with lab stub via settings; `LabIdentityMap` in `ara.identity_map` wired on notify (shared-channel delivery still used); Graph stub docs match delegated Reviewer-only Apply. Tests in `tests/test_lab_apply_contract.py`.
