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

# --- Track background PIDs ---
pids=()

# --- Paths and files ---
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
OUTPUT_DIR=$(realpath "$SCRIPT_DIR/../certificates")
CA_CERT="$OUTPUT_DIR/ca.crt"
SERVER_CERT="$OUTPUT_DIR/server.crt"
SERVER_KEY="$OUTPUT_DIR/server.key"
HELLO_FILE="hello.html"

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
    make FEATURES=tls
fi

# 3. Start socat in background (output to file)
echo "[*] Starting socat in background..."
socat -d -d VSOCK-LISTEN:12345,reuseaddr TCP:localhost:$PORT > socat.log 2>&1 &

# 4. Example file creation
echo "Creating example file to serve..."
echo "Hello, World!" > "$HELLO_FILE"

# 5. Start openssl s_server in background (output to file)
echo "[*] Starting openssl s_server in background..."
openssl s_server \
    -key "$SERVER_KEY" \
    -cert "$SERVER_CERT" \
    -port "$PORT" \
    -tls1_3 \
    -WWW \
    -keylogfile tls_keylog.log \
    > /dev/null 2>&1 &
pids+=($!)

# 6. Launch guest VM (this stays in foreground)
echo "[*] Launching guest with QEMU=$QEMU ..."
"$SCRIPT_DIR/launch_guest.sh" --nocc --vsock 3
