# RVA Inbox Check

A sanitized-data suspicious-email screening pilot for RVA Cyber, with personal invitations and reusable group signup links.

**Not a safety certificate.** This screens visible evidence. It does not authenticate senders, resolve hidden links, inspect remote URLs, scan attachments, or prove that a message is safe. Do not submit PHI, client material, confidential information or live credentials to this pilot.

## What it does
- Paste text, paste a screenshot, drag/drop, or choose PNG/JPG/WebP/TXT/EML/Outlook MSG/text-PDF.
- Azure GPT-4.1 mini extracts screenshot text. Jev (`typesafe/jev-1.13`) returns typed decisions via OpenRouter. A separate Azure call selects IDs of relevant source excerpts. Fixed rules, not generated prose, supply the assessment summary and next steps.
- Deterministic risk policy distinguishes insufficient/low-confidence evidence from concrete warning signals; no model receives tools or mailbox access.
- Explicit sharing sends a case to the reviewer queue. A human review is recorded separately from model output.
- A separate, locked-down OpenClaw agent (`agent/`) performs every web screening: the page hands it a single-use ticket, the agent calls its one tool to run the check, and writes the plain-language reply the submitter sees.
- OpenClaw tool plugin lets employees submit sanitized email evidence and request human escalation from their own agent conversation.

## Local setup
Python 3.13+, Node 24.16+/26.1+ for the optional plugin.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -r requirements-dev.txt
# Set environment via your secret manager; never commit .env files.
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8094 --no-access-log
```
Required environment:
- `DATA_ENCRYPTION_KEY`: Fernet key, e.g. generated using cryptography.Fernet.generate_key(). Back it up securely.
- `BOOTSTRAP_KEY`: random operator-only secret for creating reviewer invitations.
- `PUBLIC_ORIGIN`: exact HTTPS origin (or localhost for local development).
- `DB_PATH`: persistent SQLite path; default `/home/inboxcheck/cases.db`.
- `OPENROUTER_API_KEY`: a dedicated limited project key for wider rollout.
- `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`.
- Azure managed identity with **Cognitive Services OpenAI User**, or local `AZURE_OPENAI_API_KEY` for testing.
- `LOCAL_DEV=1` allows HTTP session cookies **only on a loopback development server**; never set on Azure.

Requests that mutate state require `Origin: <PUBLIC_ORIGIN>` and `X-Inbox-Request: 1`. Operator creates `/api/invites` with `X-Operator-Key`; body is `{ "name": "Reviewer", "role": "reviewer" }`. Deliver the resulting one-time code privately, never put it in a query string. The web UI accepts it via `/#invite=...` and immediately clears the fragment.

Session lifetime 12h; personal invitation lifetime 24h. Reviewers can issue submitter invitations or create seven-day reusable signup links from the review queue. A shared link creates a separate submitter-only guest session per browser, never reviewer access. It may be forwarded and can be disabled to stop new signups; existing sessions can be revoked separately by the operator. Display names are not verified identities; counts must not be presented as verified humans or contest installs. This is a short-lived pilot, not enterprise SSO.

A shared URL uses `/#join=...`; its enrollment code is cleared from the address bar and kept in tab-scoped session storage so an unsubmitted signup survives refresh. It is a shareable enrollment capability, not a shared account. Existing signed-in sessions are not replaced. Reviewer/operator access is required to list, create or disable shared links; active codes are encrypted at rest. Maximum ten links and 100 retained participant identities; signup and analysis limits are distinct. No signup emails are sent.

## Tests
```sh
.venv/bin/python -m pytest -q
cd integrations/openclaw
npm ci --ignore-scripts
npm run plugin:validate
npm test
```
`tests/preview_server.py` is a **local-only mock** browser preview. `tests/live_smoke.py` uses real providers with synthetic examples and removes its cases. Its results are not an accuracy benchmark.

## Privacy and security boundaries
- Single tenant, single worker, single instance. SQLite is not suitable for scale-out; migrate to PostgreSQL and distributed admission before scaling.
- Case payloads are encrypted using Fernet. Keys are in Azure settings; subscription administrators can access them. This is not HSM isolation or end-to-end encryption.
- Cases expire after 24h, become inaccessible immediately, and are deleted by a minute-level purge while running. No image is retained as a case; application upload parsing stays in memory under a hard request-size limit; no plaintext spool files are created. No automatic case backups are configured.
- Case-event and numeric usage metadata expire after seven days. No prompt or screenshot telemetry. Expired tokens are purged; user display names are removed once no live session, token or retained case references the identity. Rejected-login counters are bounded to 301 rows and five minutes, without source IP retention.
- Uploaded files are processed in disposable processes with Linux memory and CPU limits, an outer timeout, and fail-closed seccomp restrictions on filesystem opening/writes, network connections and process creation. This is defense in depth, not a VM. Images are decoded and re-encoded. Text PDFs only; attachments are ignored, never executed.
- 10 attempts/user/hour and 100 attempts/global/24h by default; two concurrent model analyses; at most four admitted requests and one per identity. Allowance is reserved before parsing; malformed uploads also count. Body reads have 5-second idle / 15-second total deadlines. These application caps are not a provider-enforced dollar limit.
- Provider failures do not produce a false successful assessment. Azure explanation failure produces a clearly degraded, deterministic explanation after Jev succeeds.
- No raw HTTP access logs from the application. Reverse proxy/platform infrastructure may retain request metadata. Tokens and invitations never go in URL query parameters.
- Recognizable codes, passwords and tokens are masked in extracted text before classification/storage and quoted evidence; this is not comprehensive DLP. Screenshot pixels reach Azure OCR before text masking. Older case views use fixed guidance without rewriting their original encrypted records.
- Treat all uploaded, extracted and model-returned content as untrusted. Models have no tools. Explanation output is restricted to validated excerpt IDs; advice is deterministic. The OpenClaw plugin admits a bounded response schema, discards model-authored advice, and labels retained excerpts as untrusted. These controls do not guarantee prompt-injection resistance or classification accuracy.
- Production wheels are version-pinned and SHA256-locked; Linux builds require compatible wheels. Dev dependencies are installed separately.
- Use sanitized data only. Provider retention terms still apply. Validate separately before regulated or production company data.

## Cost and hosting
Azure Linux B1 in Central US: retail **$0.018/hour**, approximately **$13.14/730h**, verified Sep 22, 2026 via Azure Retail Prices API. Azure GPT-4.1 mini and Jev usage are additional. Single-instance hosting, no auto-scale or auto-top-up.

## The OpenClaw agent
Every web submission is screened by a dedicated OpenClaw agent running in its own container (`agent/`), built on the official OpenClaw image. Many employees use it at once through the web page, each in a separate agent session, and a human security reviewer resolves escalated cases: a multiplayer first-line security teammate.

1. The web app extracts and masks the email text, then issues a random single-use ticket bound to that user and that text (150-second lifetime, held only in memory).
2. It sends the ticket and email to the agent over the OpenClaw Chat Completions endpoint, with a per-user session key.
3. The agent's **only** tool, `inboxcheck_screen_ticket`, redeems the ticket at `/api/agent/screen` with an analyze-only token. The server classifies the exact text it stored, so email content or the model cannot change what is checked or whose case it becomes. Forged, reused or expired tickets are refused.
4. The agent writes a short reply; the web app stores it (bounded, masked, rendered as plain text) with the case. If the agent fails or skips the tool, no assessment is shown.

Agent boundaries: tool profile `minimal` plus that one tool; no shell, file, web, browser, messaging or session tools; only the Inbox Check plugin is allowed to load; no cross-conversation memory; Azure OpenAI model; OpenClaw state is local and ephemeral, so transcripts disappear on restart. The gateway token equals operator access, so the agent app accepts traffic only from the web app's outbound addresses. The container reports daily per-model token counts to the [AI Worth Using Agent Index](https://aiworthusing.com/agent-index/rva-inbox-check) with Plow's pinned `agent_index_client.py` (Apache-2.0, © The Plow Collective); no prompts or email content are sent.

```sh
docker build -f agent/Dockerfile -t inbox-check-agent .
# Required environment: AZURE_OPENAI_V1_URL, AZURE_OPENAI_API_KEY, OPENCLAW_GATEWAY_TOKEN,
# INBOXCHECK_ENDPOINT (web app origin), INBOXCHECK_AGENT_TOKEN (analyze-only, from /api/agent-token)
# Web app: AGENT_GATEWAY_URL (agent origin) and AGENT_GATEWAY_TOKEN
```
