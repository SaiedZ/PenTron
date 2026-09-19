#!/usr/bin/env bash
set -e

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
OLLAMA_HOST="${OLLAMA_HOST:-localhost:11434}"
OLLAMA_ONLY_HOST="${OLLAMA_HOST%%:*}"
OLLAMA_ONLY_PORT="${OLLAMA_HOST##*:}"

wait_for() {
    local host="$1"
    local port="$2"
    local label="$3"
    echo "[entrypoint] Waiting for ${label} (${host}:${port})..."
    for i in $(seq 1 60); do
        if python3 - "$host" "$port" <<'EOF'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((host, port))
    sys.exit(0)
except Exception:
    sys.exit(1)
finally:
    s.close()
EOF
        then
            echo "[entrypoint] ${label} is up."
            return 0
        fi
        sleep 2
    done
    echo "[entrypoint] WARNING: ${label} did not become reachable in time, continuing anyway."
}

wait_for "$DB_HOST" "$DB_PORT" "MariaDB"
wait_for "$OLLAMA_ONLY_HOST" "$OLLAMA_ONLY_PORT" "Ollama"

exec "$@"
