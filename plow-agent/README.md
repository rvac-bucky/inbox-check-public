# Inbox Check on Plow

A one-click Plow OpenClaw agent: text it a suspicious email and it screens it with RVA Cyber's
Inbox Check service, explains the warning signs, and can send risky ones to a human reviewer.

- `Dockerfile` builds `FROM` the Plow OpenClaw base, pinned by digest, with `AGENT_ID=rva-inbox-check`.
- `skills/inbox-check/screen.mjs` needs no credentials. Each install opens its own private guest
  session on the public service and keeps the session cookie in `/var/lib/plow/inbox-check` (0600).
- `PLOW_THREAD_TRUST=untrusted`: only the owner can run the screening tool.

Published image: `ghcr.io/rvac-bucky/inbox-check-plow` (built by `.github/workflows/plow-image.yml`).
