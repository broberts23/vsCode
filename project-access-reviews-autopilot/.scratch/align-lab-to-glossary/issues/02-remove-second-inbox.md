# 02: Remove second inbox (SPA + pending API)

**What to build:** Operators inject Review Work only via the simulate API and simulator CLI/job. The SPA and pending-list API are gone, including SPA client configuration in infra. Health and Slack interactivity keep working; demos no longer depend on a second UI.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] SPA static app is removed from the product surface
- [ ] `GET` pending-list API is removed (and store helpers that exist only to feed it)
- [ ] SPA client id / related deploy config is removed or no longer required
- [ ] Simulate API (OIDC-protected) and simulator CLI/job still publish Review Work
- [ ] Health check and Slack interactivity paths still function
- [ ] Tests at the HTTP/domain seam prove the pending route is absent and simulate still publishes
- [ ] README/demo steps no longer instruct serving the SPA (full narrative polish can wait for ticket 06)
