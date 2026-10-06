# Inbox Check

Open-source email risk screening with the same clear result on the web and by email. **MIT licensed.** Bring your own model keys, domain, and Microsoft 365 receiving address, such as `test@your-domain.example`. No RVA Cyber account, agent subscription, or registration is required to self-host.

**Screening, not a safety certificate:** it evaluates supplied content. It does not authenticate the original sender, visit links, detonate attachments, or establish that an email is safe. Use sanitized examples; do not submit sensitive or regulated data without separately evaluating your hosting and provider arrangements.

## What changed

- One typed classification request on the default path. Evidence excerpts and next steps are assembled deterministically—no second agent can contradict the verdict or invent advice.
- GREEN means no obvious warning signs, **not** “safe.” YELLOW separates uncertain checks from warning signs. RED gives specific actions to avoid.
- Text and HTML email alternatives are both considered. Declared HTML links are preserved as evidence; overlong emails are rejected rather than silently cut.
- Retryable mail failures retain work. Accepted sends are recorded before cleanup. Ambiguous send outcomes are held for operator review, never blindly replayed.
- Private cases, encrypted storage, 24-hour case expiry, bounded rate limits, and Linux-isolated upload parsing.

## Quick start: Linux / Docker

Requirements: Docker Engine with Compose, an OpenRouter key for the typed classifier, and a vision/JSON-capable OpenAI-compatible endpoint or Azure OpenAI deployment for screenshots. Provider usage and hosting may cost money; this software is free. Set spending limits at your providers.

```sh
git clone https://github.com/rvac-bucky/inbox-check-public.git
cd inbox-check-public
python3 scripts/setup_env.py
# Edit .env privately; generated keys are never printed.
# Add OPENROUTER_API_KEY, then either AI_* or AZURE_OPENAI_*.
docker compose up --build -d
```

Open `http://127.0.0.1:8094`. Configuration validation fails with setting **names**, not secret values, when required setup is missing. The example is web-only until you configure all `MAILCHECK_*` identity/mailbox fields. The Docker image runs as non-root, with a read-only root filesystem and a persistent data volume. Use one worker and one instance.

**Do not publish the loopback development settings.** For your domain, configure a TLS reverse proxy to `127.0.0.1:8094`, set `PUBLIC_ORIGIN=https://check.your-domain.example`, set `LOCAL_DEV=0`, and recreate the service. [Full setup](docs/SELF_HOSTING.md).

## Supported inputs

Paste text or upload PNG, JPEG, WebP, UTF-8 TXT, EML, Outlook MSG, or a text-based PDF. Files are bounded to 8 MB; messages to 50,000 characters. Images are re-encoded; PDF text is limited to five pages. Embedded attachments are **not** scanned. HEIC is not supported.

For email intake, forward inline or attach an EML/Outlook email item. The mailbox integration currently supports **Microsoft 365 Graph**, not arbitrary IMAP/SMTP or Gmail. Any address on your verified Microsoft 365 domain can be configured, provided its app access is scoped correctly. Forwarded MSG file attachments are not currently an email-intake format; upload MSG through the web page instead.

## How decisions work

1. Extract content without opening URLs or executing attachments. Mask recognizable secrets; masking is not comprehensive DLP.
2. Ask the typed classifier about actual requests for secrets, unusual payments, visible identity mismatches, pressure, marketing, and insufficient content. Prompts distinguish code delivery and training examples from actual requests to disclose secrets.
3. Validate the response and apply documented conservative rules. A credible secret request cannot be GREEN. Uncertainty is not automatically evidence of phishing. Model scores are not calibrated probabilities of safety.
4. Produce fixed advice and bounded, redacted excerpts from the submitted text. The email and web interfaces use the same verdict definitions and explanation payload.

A provider refusal is a processing limitation, not proof of malicious intent. An optional AI evidence selector and optional OpenClaw adapter remain for integrations; neither is needed on the default path. See [architecture and reliability](docs/ARCHITECTURE.md).

## Configuration at a glance

| Setting | Purpose |
|---|---|
| `PUBLIC_ORIGIN` | Your exact externally visible HTTPS origin |
| `DATA_ENCRYPTION_KEY` | Generated Fernet key; preserve securely across deployments |
| `BOOTSTRAP_KEY` | Generated operator key; never expose to regular users |
| `OPENROUTER_API_KEY` | Your dedicated spending-capped classifier credential |
| `CLASSIFIER_MODEL` | Typed decisions model; default `typesafe/jev-1.13` |
| `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL` | Optional alternative to Azure for OCR / optional evidence selection |
| `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_KEY` | Azure option; managed identity may replace the key |
| `MAILCHECK_MAILBOX` + tenant/client/secret | Your Microsoft 365 receiving/sending mailbox |
| `SITE_NAME` | Your web application title |
| `SCREENING_ROUTE` | `direct` default; `agent` / legacy `auto` available |
| `EVIDENCE_SELECTION` | `rules` default; `ai` optional grounded excerpt selector |
| `USER_HOURLY_LIMIT`, `DAILY_ANALYSIS_LIMIT` | Attempt limits, including failed processing |

The classifier's decisions endpoint is a typed API; changing its model to an arbitrary chat model will not work. An `AI_BASE_URL` endpoint must support chat completions, JSON responses, and vision for screenshots. Compatibility is tested structurally, not promised for every provider/model.

## Test and evaluate

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
# Optional TypeScript adapter:
cd integrations/openclaw
npm ci --ignore-scripts
npm test
```

Tests cover isolation, risk rules, parser boundaries, delivery state, provider failures and configuration. Passing them is **not** proof of real-world phishing accuracy. [Evaluation notes](docs/EVALUATION.md) describe the small synthetic live corpus and its limits. `scripts/evaluate_web.py` sends only supplied synthetic fixtures to an explicitly chosen service, records outcomes, and deletes created cases.

## Privacy and operations

- Inputs are sent to your configured AI providers. Your provider agreements/retention policies apply. No analytics or contest reporting on the default application path.
- Cases and queued reply payloads are encrypted, retained for at most 24 hours while running, and purged. Delivery deduplication hashes and hold metadata last 30 days. Graph deletion moves processed source emails to the mailbox's deleted-items lifecycle; it is **not** a guarantee of immediate hard deletion from Microsoft 365.
- Unknown delivery outcomes are held for operator investigation, not labeled delivered. [Operations guide](docs/OPERATIONS.md) explains reconciliation.
- SQLite and in-process admission controls require one worker/instance. Scaling out needs a shared database, queue, and distributed limits first.
- Use your secret manager for deployment secrets; never commit `.env`, email content, tokens, databases, or deployment artifacts.

Contributions welcome: include a synthetic regression case, explain the failure being fixed, and run the tests. For suspected security issues, see [SECURITY.md](SECURITY.md). MIT terms are in [LICENSE](LICENSE).
