#!/bin/bash
set -e
trap cleanup EXIT INT TERM

# --- Cleanup function to terminate background processes ---
cleanup() {
    echo "[*] Cleaning up background processes..."
    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ -f "$HELLO_FILE" ]; then
        rm  -f "$HELLO_FILE"
    fi
}

# --- Flag default ---
GEN_CERTS=true
NO_COMPILE=false
PORT=4433
HOST="localhost"
TEST="client"

# --- Track background PIDs ---
pids=()

# --- Paths and files ---
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
OUTPUT_DIR=$(realpath "$SCRIPT_DIR/../certificates")
PYTHON_DIR=$(realpath "$SCRIPT_DIR/../examples")
CA_CERT="$OUTPUT_DIR/ca.crt"
SERVER_CERT="$OUTPUT_DIR/server.crt"
SERVER_KEY="$OUTPUT_DIR/server.key"

# --- Parsing flags ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-gen-certs|-ng)
            GEN_CERTS=false
            shift
            ;;
        --port|-p)
            PORT="$2"
            shift 2
            ;;
        --no-compile|-nc)
            NO_COMPILE=true
            shift
            ;;
        --qemu)
            QEMU="$2"
            shift 2
            ;;
        --host)
            HOST="$2"
            shift 2
            ;;
        --test|-t)
            if [[ "$2" != "client" && "$2" != "server" ]];
            then
                echo "Error: Invalid test type '$2'. Use 'client' or 'server'."
                exit 1
            fi
            TEST="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# 1. Generate certificates if needed
if [ "$GEN_CERTS" = true ]; then
    rm -rf "$OUTPUT_DIR"
    echo "[*] Generating new certificates..."
    "$SCRIPT_DIR/gen_ca_server_certs.sh"
else    
    if [ ! -f "$CA_CERT" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
        echo "Error: Certificates not found in $OUTPUT_DIR. Please run without --no-gen-certs to generate them."
        exit 1
    else
        echo "[*] Using existing certificates in $OUTPUT_DIR"
    fi
fi

# 2. Build with TLS feature
if [ "$NO_COMPILE" = true ]; then
    echo "[*] Skipping compilation as per --no-compile flag."
else
    echo "[*] Building with TLS feature..."
    make FEATURES=tls,"$TEST"
fi

# 3. Start socat in background
echo "[*] Starting socat in background..."
socat -d -d VSOCK-LISTEN:12345,reuseaddr,fork TCP:$HOST:$PORT > /dev/null 2>&1 &
pids+=($!)

# 4. Start python in background
if [ "$TEST" = "server" ]; then 
    PYTHON_SCRIPT="$PYTHON_DIR/web_client.py"
elif [ "$TEST" = "client" ]; then
    PYTHON_SCRIPT="$PYTHON_DIR/web_server.py"
fi

echo "[*] Starting python in background..."
"$PYTHON_SCRIPT" "$SERVER_KEY" "$SERVER_CERT" "$PORT" "$HOST" > /dev/null 2>&1 &
pids+=($!)

# 5. Launch guest VM (this stays in foreground)
echo "[*] Launching guest with QEMU=$QEMU ..."
"$SCRIPT_DIR/launch_guest.sh" --nocc --vsock 3
