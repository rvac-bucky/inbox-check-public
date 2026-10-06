# Operations

- Use `docker compose logs --tail=100 inboxcheck` for non-content failure codes. Keep platform/proxy log retention appropriate for your environment.
- `GET /healthz` tests app liveness. It does not spend model credits or prove mail delivery.
- `GET /api/operator/status` with `X-Operator-Key` returns mailbox enabled state and work counts (`working`, `retry`, `sending`, `uncertain`, `failed`). It contains no addresses or message text. Alert on held work and growing retry counts.
- An accepted Graph `sendMail` request is not proof of inbox delivery. Validate real synthetic replies and use your provider's message trace for missing mail.

## Held delivery

A `sending` or `uncertain` state means delivery may have happened. Do not mass-reset it. Inspect the retained source in the tester Inbox and Exchange message trace, using the original sender/time/subject. If delivery is proven, mark the hash handled; if non-delivery is proven, an operator may reset only that record to `retry`. Use a controlled private database tool, preserve an audit record, and never expose decrypted queued replies in logs. After the 24-hour content lifetime, request a new submission instead of replaying an expired result. Source messages held for review are marked read, not deleted.

No automated “LLM recovery agent” is required or recommended. Investigate provider auth/quota first, then deterministic processing/state errors. Avoid retrying authentication failures indefinitely.

## Releases and rollback

Back up application source and secret configuration securely. Do not add private case data to source archives or public backups. Deploy new code while preserving the encryption key and data volume; run configuration validation and one benign/one phishing synthetic end-to-end check. `mail_work` is an additive table. Rolling back to an older release that does not understand it requires pausing mail polling and reconciling pending/held work first—blind rollback could resend previously ambiguous messages. Web-only rollback does not require deleting data.

Review provider spending limits and rate-limit counters. Do not increase caps automatically. Maintain one instance/worker until a distributed datastore/queue is designed and tested.
