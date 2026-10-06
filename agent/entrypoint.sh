#!/bin/sh
# Inbox Check agent container. OpenClaw state is local and ephemeral (transcripts vanish on
# restart); only the Agent Index reporter identity lives on the persistent $HOME.
set -eu
: "${AZURE_OPENAI_API_KEY:?}" "${AZURE_OPENAI_V1_URL:?}" "${OPENCLAW_GATEWAY_TOKEN:?}" "${INBOXCHECK_ENDPOINT:?}" "${INBOXCHECK_AGENT_TOKEN:?}"
# App Service mounts $HOME from shared storage with permissive modes; keep every OpenClaw
# temp/cache path on private local disk so its safety checks pass.
export TMPDIR="$OPENCLAW_STATE_DIR/tmp" XDG_CACHE_HOME="$OPENCLAW_STATE_DIR/cache" XDG_CONFIG_HOME="$OPENCLAW_STATE_DIR/xdg-config"
mkdir -p "$OPENCLAW_STATE_DIR/workspace" "$HOME" && mkdir -m 700 -p "$TMPDIR" "$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" && (mkdir -m 700 -p /tmp/openclaw 2>/dev/null || true)
cp /opt/inboxcheck/openclaw.json "$OPENCLAW_CONFIG_PATH"
cp /opt/inboxcheck/AGENTS.md "$OPENCLAW_STATE_DIR/workspace/AGENTS.md"
if [ "${INBOXCHECK_TELEMETRY:-0}" = "1" ] && [ -n "${AGENT_ID:-}" ] && [ -f "$HOME/.agent-index/.agent-index.json" ]; then
  ( sleep 90; while true; do python3 /opt/inboxcheck/agent_index_client.py --agent "$AGENT_ID" 2>&1 | sed 's/^/[agent-index] /' || true; sleep 300; done ) &
fi
exec node /app/openclaw.mjs gateway
