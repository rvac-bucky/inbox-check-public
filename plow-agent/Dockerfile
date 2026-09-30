# Inbox Check on the Plow OpenClaw base image (plow-pbc/plow-openclaw-agent, commit 771198a).
# Pinned by digest: the base boots holding the agent's Plow credential.
FROM public.ecr.aws/e1h7x4a2/plow-cloud-agents:base-771198a9609dcef54d44843e7da5329c17fa51b4@sha256:f1e7c421b97a80f1bd17015f96daceb965f350a241f7edc7e4d856a0e3a6f8f5

# Agent Index listing this install reports as.
ENV AGENT_ID=rva-inbox-check \
    AGENT_NAME="Inbox Check" \
    AGENT_BLURB="Text it a suspicious email. It flags phishing signs, says what to do next, and can route risky ones to a human security reviewer." \
    PLOW_THREAD_TRUST=untrusted

LABEL org.opencontainers.image.source="https://github.com/rvac-bucky/inbox-check-public" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Inbox Check (Plow OpenClaw agent)"

USER root
# This agent screens messages people share. It gets no Mac or mailbox skills.
RUN rm -rf /opt/plow/skills/owners-mac /opt/plow/skills/google-workspace
COPY prompt/AGENTS.md /opt/plow/prompt/AGENTS.md
COPY skills/ /opt/plow/skills/
RUN chmod -R a+rX,go-w /opt/plow/prompt /opt/plow/skills
USER node
