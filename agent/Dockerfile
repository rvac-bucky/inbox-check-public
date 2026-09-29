# Inbox Check screening agent: official OpenClaw image, one plugin tool, no shell or file tools.
# Build from the repository root: docker build -f agent/Dockerfile .
FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS plugin
WORKDIR /src
COPY integrations/openclaw/package.json integrations/openclaw/package-lock.json integrations/openclaw/tsconfig.json ./
COPY integrations/openclaw/src ./src
RUN npm ci --ignore-scripts && npx tsc -p tsconfig.json && npm prune --omit=dev --omit=peer --ignore-scripts

FROM ghcr.io/openclaw/openclaw:2026.9.6@sha256:0a5ff5e682e62afa19149df126aa50063bf65ef885b5c94713ce32dc0eb12e15
USER root
RUN mkdir -p /opt/inboxcheck/plugin /var/lib/openclaw /home/inboxcheck-agent && chown node:node /var/lib/openclaw /home/inboxcheck-agent
COPY --from=plugin /src/dist /opt/inboxcheck/plugin/dist
COPY --from=plugin /src/node_modules /opt/inboxcheck/plugin/node_modules
COPY integrations/openclaw/openclaw.plugin.json integrations/openclaw/package.json /opt/inboxcheck/plugin/
COPY agent/openclaw.json agent/AGENTS.md agent/entrypoint.sh agent/agent_index_client.py /opt/inboxcheck/
# Agent Index client pinned to the same commit and checksum Plow's base image uses.
RUN echo "5be521644ade0f041e83370ac457edc8ad85410e14265f1b1243807772de9a5b  /opt/inboxcheck/agent_index_client.py" | sha256sum -c - \
 && chmod -R a+rX,go-w /opt/inboxcheck && chmod 0755 /opt/inboxcheck/entrypoint.sh
ENV OPENCLAW_STATE_DIR=/var/lib/openclaw OPENCLAW_CONFIG_PATH=/var/lib/openclaw/openclaw.json OPENCLAW_NO_RESPAWN=1 \
    HOME=/home/inboxcheck-agent AGENT_ID=rva-inbox-check AGENT_RUNTIME=OpenClaw
EXPOSE 8080
USER node
ENTRYPOINT ["/opt/inboxcheck/entrypoint.sh"]
