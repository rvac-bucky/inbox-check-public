# Architecture and decision policy

Default path: browser/email → bounded extraction → recognizable-secret masking → typed classification → validated conservative policy → deterministic explanation → encrypted case + rendered result.

## Trust boundaries

Email bodies, HTML alternatives, URLs, screenshots, quoted headers, and model output are data, never instructions. The classifier cannot fetch URLs or call tools. The optional agent can only redeem a bound screening ticket; its free-form reply is never presented as authoritative advice. Screenshot pixels go to OCR before text redaction. Excerpts are redacted and rendered as text, not HTML.

## Decision rules (version 3)

- A secret-disclosure score of at least .7 forces likely phishing.
- Without concrete secret/payment/identity evidence, high incompleteness or very low classifier confidence gives insufficient evidence, not an accusation.
- Concrete payment/identity evidence cannot be overridden by a benign/unknown raw choice.
- A possible secret/payment/identity warning of at least .4 prevents a GREEN result.
- Advertising, urgency alone, and provider refusals do not establish malicious intent. A refused optional evidence-selection check can move a low-warning result to incomplete; it cannot invent an attack signal.

Scores and thresholds are policy inputs, not calibrated real-world probabilities. The current classifier can still make mistakes, particularly with unfamiliar languages, subtle impersonation, visual tricks, incomplete forwards, or context outside the message. No automatic action is taken on the original email.

## Durable email state

`mail_work` holds an encrypted proposed reply and bounded attempt/lease metadata. Before provider processing, work is claimed under a SQLite immediate transaction. Pre-send failures retry after bounded backoff (three attempts maximum). A definite 401/403/429 rejection can retry the saved reply without reclassifying. Before a send, state becomes `sending`; if the outcome is ambiguous, it stays held. HTTP acceptance is committed to `mail_seen` before source cleanup. Cleanup failures cannot trigger another reply.

This provides conservative duplicate avoidance, **not exactly-once external email delivery**. A crash between Graph acceptance and local commit is intrinsically ambiguous. Operators reconcile held mail against delivery evidence rather than replaying it blindly. Held source messages are retained in Inbox and marked read so they do not starve new work. Processed originals follow Exchange deleted-item retention. Default single-worker/instance operation is mandatory.

## Storage

Encrypted cases and queued reply content expire after 24 hours while the app is running. Held metadata and deduplication hashes expire after 30 days. Encryption-key rotation includes pending replies. Case/session isolation, one-time invites, CSRF/origin checks, upload admission and parser seccomp remain enforced. The operator status endpoint exposes counts only and requires the operator key; public health reports process liveness, not guaranteed provider/mailbox availability.
