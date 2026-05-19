#!/usr/bin/env bash
# Supervises two processes inside one container: the local nym-client and the
# Node P2PSH server. If either exits the container exits — Docker / Kubernetes
# can then restart the whole pod.

set -euo pipefail

NYM_HOME="${HOME}/.nym"
CLIENT_ID="${NYM_CLIENT_ID:-p2psh}"
# Keep nym-client output inside HOME (/data/home) instead of /tmp. /tmp is
# world-readable to other processes in the same pid namespace; the log holds
# gateway identifiers and connection diagnostics we don't want casually leaked.
# Mode 0600 tightens it further so even another uid in the same volume can't
# read it.
NYM_LOG_DIR="$NYM_HOME/run"
NYM_LOG="$NYM_LOG_DIR/nym-client.log"

mkdir -p "$HOME" "$NYM_LOG_DIR"
: > "$NYM_LOG"
chmod 600 "$NYM_LOG"

# Initialize nym-client on first run. After that the config + key material
# under /data/home/.nym/clients/<id> is reused.
if [[ ! -d "$NYM_HOME/clients/$CLIENT_ID" ]]; then
    echo "[entrypoint] initializing nym-client identity '$CLIENT_ID'..."
    nym-client init --id "$CLIENT_ID"
fi

# Launch nym-client in the background. Its native WS interface comes up on
# 127.0.0.1:1977 once gateway authentication completes.
nym-client run --id "$CLIENT_ID" >"$NYM_LOG" 2>&1 &
NYM_PID=$!

cleanup() {
    echo "[entrypoint] shutting down..."
    kill "$NYM_PID" 2>/dev/null || true
    kill "$SERVER_PID" 2>/dev/null || true
    wait
}
trap cleanup TERM INT

# Wait for the nym-client to declare itself ready before starting the server,
# so the server's WS connect to 127.0.0.1:1977 doesn't race the gateway dial.
echo "[entrypoint] waiting for nym-client to be ready..."
for _ in $(seq 1 90); do
    if grep -q "Client startup finished" "$NYM_LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$NYM_PID" 2>/dev/null; then
        echo "[entrypoint] nym-client died before becoming ready:"
        cat "$NYM_LOG"
        exit 1
    fi
    sleep 1
done

echo "[entrypoint] starting P2PSH server..."
node --import tsx/esm src/server/main.ts &
SERVER_PID=$!

# Whichever exits first brings the container down.
wait -n "$NYM_PID" "$SERVER_PID"
EXIT_CODE=$?
echo "[entrypoint] a child process exited with code $EXIT_CODE"
cleanup
exit "$EXIT_CODE"
