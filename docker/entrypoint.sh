#!/usr/bin/env bash
# Supervises two processes inside one container: the local nym-client and the
# Node P2PSH server. If either exits the container exits — Docker / Kubernetes
# can then restart the whole pod.

set -euo pipefail

NYM_HOME="${HOME}/.nym"
CLIENT_ID="${NYM_CLIENT_ID:-p2psh}"

mkdir -p "$HOME"

# Initialize nym-client on first run. After that the config + key material
# under /data/home/.nym/clients/<id> is reused.
if [[ ! -d "$NYM_HOME/clients/$CLIENT_ID" ]]; then
    echo "[entrypoint] initializing nym-client identity '$CLIENT_ID'..."
    nym-client init --id "$CLIENT_ID"
fi

# Launch nym-client in the background. Its native WS interface comes up on
# 127.0.0.1:1977 once gateway authentication completes.
nym-client run --id "$CLIENT_ID" >/tmp/nym-client.log 2>&1 &
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
    if grep -q "Client startup finished" /tmp/nym-client.log 2>/dev/null; then
        break
    fi
    if ! kill -0 "$NYM_PID" 2>/dev/null; then
        echo "[entrypoint] nym-client died before becoming ready:"
        cat /tmp/nym-client.log
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
