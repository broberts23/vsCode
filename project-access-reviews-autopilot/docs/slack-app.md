# Slack app (developer sandbox)

1. Create a [Slack developer sandbox](https://docs.slack.dev/tools/developer-sandboxes/) if you do not have a free workspace.
2. Create an app from scratch.
3. **OAuth & Permissions** bot scopes: `chat:write`, `chat:write.public` (or invite the bot to a channel).
4. Install to workspace; copy Bot User OAuth Token (`xoxb-...`).
5. **Basic Information** → Signing Secret.
6. **Interactivity & Shortcuts** → enable; Request URL:
   - Local: use Slack **Socket Mode** (App-Level Token with `connections:write`) OR a tunnel to `https://<host>/slack/interactions`
   - Azure: `https://<api-fqdn>/slack/interactions`
7. Store secrets in Key Vault (Azure) or `.env` (local only):
   - `slack-signing-secret`
   - `slack-bot-token`
8. Set `SLACK_CHANNEL_ID` to the channel ID where cards should land.

Slack workspace **login** SSO is SAML and paid. This project does not configure it. Entra OIDC is on the SPA/API.
