# Self-hosting

## 1. Provider setup

Create a dedicated OpenRouter key with an explicit spend ceiling for the typed classifier. Set `OPENROUTER_API_KEY`. The default model uses OpenRouter's decisions API, not ordinary chat completions.

For screenshot OCR, choose either:

- Azure: set your `AZURE_OPENAI_ENDPOINT` and deployment. Use `AZURE_OPENAI_API_KEY`, or assign your host's managed identity the **Cognitive Services OpenAI User** role on that Azure resource.
- Compatible API: set `AI_BASE_URL` (including `/v1` when appropriate), `AI_API_KEY`, and `AI_MODEL`. This takes precedence over Azure. The model must support vision, JSON output and chat completions.

No model key comes with this repository. Do not use a provider key shared with unrelated systems. The optional AI evidence selector can use the same endpoint; default rule-based explanations do not call it.

## 2. Create secrets

`python3 scripts/setup_env.py` creates `.env` with random encryption/operator keys and owner-only permissions. It refuses to replace an existing file. Fill provider settings privately. Keep a protected copy of the encryption key: losing it makes stored cases unreadable. Never generate a fresh encryption key on each startup.

Docker Compose loads `.env`. For a native Python deployment, inject the same variables through your service manager/secret store; the app does not implicitly load `.env`. Set `DB_PATH` to a private writable path and run `python -m app.configuration` first. On Linux install `libseccomp2`; parser isolation fails closed when unavailable. Non-Linux native mode is development-only and lacks Linux syscall isolation.

## 3. Domain and HTTPS

Create DNS for your domain pointing to your server or proxy. Terminate TLS with a trusted certificate and proxy to the loopback-bound service. Example Caddy configuration:

```caddy
check.your-domain.example {
    reverse_proxy 127.0.0.1:8094
}
```

Set `PUBLIC_ORIGIN=https://check.your-domain.example`, `LOCAL_DEV=0`; recreate the app. The origin must exactly match browser requests. Only add an old trusted hostname to `ADDITIONAL_PUBLIC_ORIGINS` when deliberately supporting it. Never use a wildcard. Do not expose unencrypted app port 8094 publicly. Configure your proxy request-size limit to at least the application's 8 MB upload size, plus multipart overhead.

## 4. Your own test@ mailbox (Microsoft 365)

1. Provision your desired mailbox, for example `test@your-domain.example`, on your Microsoft 365 tenant. Confirm inbound and outbound mail work normally.
2. Register a dedicated Entra application. Configure application access for Microsoft Graph mail read/write and send, with administrator consent. **Constrain it to this mailbox** using your tenant's supported Exchange application RBAC/access-policy mechanism. Verify other mailboxes return access denied before enabling polling.
3. Set `MAILCHECK_TENANT_ID`, `MAILCHECK_CLIENT_ID`, `MAILCHECK_CLIENT_SECRET`, and `MAILCHECK_MAILBOX`. A partial setup is rejected by configuration validation.
4. Optionally set `MAILCHECK_INTERNAL_DOMAINS` to domains in the **same Exchange tenant**, never arbitrary external domains. External replies require aligned DMARC pass; internal exemptions also require Exchange's Internal authentication stamp. Receiving Exchange must strip untrusted organization/authentication headers. Do not reuse these header assumptions with a different mail transport.
5. Configure SPF, DKIM and DMARC for your sending domain using your mail provider's instructions. Do not set permissive “allow all” rules or disable anti-phishing globally. If your own security controls quarantine test submissions, use a narrowly scoped security-operations mailbox policy reviewed for your tenant.
6. Restart/recreate the application with the settings. Send a synthetic normal note and a synthetic credential-request example; confirm one correctly classified reply to each. Send an automated reply and confirm no response loop.

The mailbox account is not the original sender being screened. Authenticating the person forwarding a message only permits a reply; it does not make the forwarded email trustworthy. There is no Gmail/IMAP connector in this release.

## 5. Reviewer access

Guest web sessions are available without invitations and cannot see one another's cases. To create a reviewer, use `POST /api/invites` with the exact `Origin`, `X-Inbox-Request: 1`, and your private `X-Operator-Key`, plus JSON `{"name":"Reviewer","role":"reviewer"}`. Do this from a protected operator client; do not paste keys into shared shell history. The one-time invitation is a capability: deliver privately, never commit it. The reviewer sees only own cases or explicitly shared cases.

## 6. Optional agent integration

Default `SCREENING_ROUTE=direct` does not call an agent or consume an agent subscription. The `agent/` image and OpenClaw plugin are optional. With `SCREENING_ROUTE=agent`, configure an HTTPS `AGENT_GATEWAY_URL` and `AGENT_GATEWAY_TOKEN`; provision the analyze-only app token for its plugin. Limit inbound gateway traffic to your application. The adapter redeems a short-lived single-use ticket for the exact submitted content. Free-form agent advice is discarded. A valid classification survives a failed agent reply; otherwise the same classifier runs directly.

The historical Agent Index reporter is opt-in (`INBOXCHECK_TELEMETRY=1`) and requires a separately provisioned reporter identity. Leave it disabled for ordinary self-hosting. No registration with RVA Cyber or contest infrastructure is required.
