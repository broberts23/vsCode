# 02: Remove second inbox (SPA + pending API)

**What to build:** Operators inject Review Work only via the simulate API and simulator CLI/job. The SPA and pending-list API are gone, including SPA client configuration in infra. Health and Slack interactivity keep working; demos no longer depend on a second UI.

**Blocked by:** None (can start immediately).

**Status:** resolved

- [x] SPA static app is removed from the product surface
- [x] `GET` pending-list API is removed (and store helpers that exist only to feed it)
- [x] SPA client id / related deploy config is removed or no longer required
- [x] Simulate API (OIDC-protected) and simulator CLI/job still publish Review Work
- [x] Health check and Slack interactivity paths still function
- [x] Tests at the HTTP/domain seam prove the pending route is absent and simulate still publishes
- [x] README/demo steps no longer instruct serving the SPA (full narrative polish can wait for ticket 06)

## Answer

Removed `spa/`, `GET /api/pending`, `list_pending`, and SPA client id from settings/infra/deploy/Dockerfile. Simulate + health remain; tests in `tests/test_api_inbox_surface.py`. Blog rewrite deferred to ticket 06.
