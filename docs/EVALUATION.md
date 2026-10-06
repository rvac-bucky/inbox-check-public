# Evaluation methodology

## What the tests establish

Automated tests exercise decision-policy boundaries, malformed responses, isolation, extraction, key rotation, provider/agent failures, email retry and ambiguous-send handling, self-host configuration, and safe rendering. They establish repeatable behavior for those examples—not universal phishing detection.

`tests/fixtures/screening_corpus.json` contains only synthetic messages. It includes ordinary correspondence, requested sign-in codes, credential theft, bank-change fraud, quoted security training, normal invoices, gift-card impersonation, malicious “training,” prompt injection, fake security banners, awareness reminders, newsletters, and incomplete evidence. Labels are engineering expectations, not independently adjudicated ground truth. Borderline fraud may reasonably be RED or YELLOW; the file records acceptable categories explicitly.

Run against a service you operate and have permission to test:

```sh
.venv/bin/python scripts/evaluate_web.py \
  --origin https://check.your-domain.example \
  --output evaluation.json
```

This spends the service's provider allowance. It creates a fresh synthetic guest session every seven examples, retains normal per-user/global limits, records elapsed time and fallback state, and deletes every successfully created test case. Do not run against a third-party service without authorization. It does not change provider limits. Test identities are not human users or adoption metrics.

Compare category matches, completion failures, explanation fallbacks and timing separately. A faster result is not a better result if false negatives increase. Store results privately if you replace any fixtures with sensitive content; the included fixtures need no real credentials or functioning malicious domains.

## October 6 baseline

The six initial live web examples returned expected categories; three real email submissions received expected reply categories. One of six web explanations fell back after invalid evidence-selection output. This was a small baseline, not an accuracy estimate. Improvements target reproduced failure modes: discarded completed checks, unsupported claims from content-filter refusal, hidden HTML evidence, overlong-email truncation, and delivery loss/duplication risks.

## October 6 live verification after repairs

- 14/14 synthetic text submissions matched the accepted categories, with no failed requests or explanation fallbacks. Created web cases were deleted.
- On the same six baseline messages, median request time decreased from 8.75 seconds to 1.09 seconds. This is a small sequential sample, not a latency SLA.
- Three new real email submissions produced the expected reply categories (ordinary note GREEN, credential request RED, quoted training GREEN).
- An EML with benign plain text but a malicious HTML alternative was correctly flagged RED. A synthetic screenshot was also flagged RED.
- Production storage fingerprints verified all three pre-existing unexpired cases unchanged across deployment. No claim is made about real-user accuracy from these synthetic examples.

## Remaining validation needs

Independent held-out human-labeled corpora, multilingual coverage, image-only attacks, compromised legitimate sender scenarios, and longer-running load/delivery measurements remain necessary before broad accuracy or availability claims. Neither the synthetic corpus nor a clean unit suite substitutes for those evaluations. This release does not fetch URLs, scan attachments, or authenticate the original forwarded sender.
