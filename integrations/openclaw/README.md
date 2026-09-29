# RVA Inbox Check OpenClaw tool

Tool: `inboxcheck_screen_email`. Host compatibility tested against OpenClaw 2026.9.4; APIs are experimental.

## Install into an isolated pilot
Build from the source in this repository:
```sh
npm install --ignore-scripts
npm run plugin:build
npm run plugin:validate
npm test
openclaw plugins install /absolute/path/to/integrations/openclaw
```
Do not point this at a production agent before reviewing the manifest and source. Do not silently change a user's model route.

Plugin configuration:
```json
{
  "endpoint": "https://YOUR-PILOT.azurewebsites.net",
  "tokenEnv": "INBOXCHECK_AGENT_TOKEN"
}
```
A signed-in reviewer creates a seven-day analyze-only token with POST `/api/agent-token` (`{"name":"My OpenClaw pilot"}`). Store it as a secret-backed environment variable, never in model prompts. Revoke using POST `/api/agent-token/{id}/revoke`. The token cannot list/read existing cases, create invites, or perform reviewer actions.

Allowlist `inboxcheck_screen_email` for the intended pilot agent. Each invocation must reflect the submitting user's permission and sanitized data confirmation. `shareForReview` requires explicit permission; otherwise the case remains inaccessible to human reviewers and expires. Screenshot users should use the web intake; text may be submitted directly in a private agent conversation.

A real isolated OpenClaw 2026.9.4 engine turn passed with Azure GPT-4.1 mini: exactly one tool call, zero failures, live Jev assessment and sharing into the human review queue. This is synthetic integration evidence, not real-user adoption or a completed contest deployment. A persistent pilot channel, real users, index reporting and public-source permission remain. Never count synthetic tests as adoption.

Installation requires explicit capability acceptance after source review: use `openclaw plugins install --link /path/to/plugin --force --accept-capabilities` in the intended isolated pilot state, then confirm `plugins inspect`. Bare `plugins.load.paths` did not provide callable tools in the integration test. Do not change the production agent config to troubleshoot this.

## Hostile-input boundary
Email input and all returned excerpts are untrusted data. The plugin limits streamed responses to 32,000 bytes under its request deadline, validates the allowed schema/enum values, discards model-authored advice and metadata, and forwards only risk/signals, case identifier and explicitly labeled untrusted excerpts with fixed safety guidance. Unexpected fields, malformed UTF-8, oversized or stalled responses fail closed. The model/agent must not obey excerpt instructions. This is not a proof of injection immunity.
