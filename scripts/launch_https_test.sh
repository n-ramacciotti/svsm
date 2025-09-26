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

# --- Track background PIDs ---
pids=()

# --- Paths and files ---
OUTPUT_DIR="certificates"
CA_CERT="$OUTPUT_DIR/ca.crt"
SERVER_CERT="$OUTPUT_DIR/server.crt"
SERVER_KEY="$OUTPUT_DIR/server.key"
HELLO_FILE="hello.html"

# LAUNCH_GUEST_SCRIPT_ARGS=()

# --- Parsing flags ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-gen-certs|-nc)
            GEN_CERTS=false
            shift
            ;;
        # --)
        #     shift
        #     LAUNCH_GUEST_SCRIPT_ARGS=("$@")  # rest of the args
        #     break
        #     ;;
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
    bash scripts/gen_ca_server_certs.sh
else    
    if [ ! -f "$CA_CERT" ] || [ ! -f "$SERVER_CERT" ] || [ ! -f "$SERVER_KEY" ]; then
        echo "Error: Certificates not found in $OUTPUT_DIR. Please run with --gen-certs to generate them."
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
socat -d -d VSOCK-LISTEN:12345,reuseaddr TCP:localhost:4433 > socat.log 2>&1 &

# 4. Example file creation
echo "Creating example file to serve..."
echo "Hello, World!" > "$HELLO_FILE"

# 5. Start openssl s_server in background (output to file)
echo "[*] Starting openssl s_server in background..."
openssl s_server \
    -key certificates/server.key \
    -cert certificates/server.crt \
    -port 4433 \
    -tls1_3 \
    -WWW \
    -keylogfile tls_keylog.log \
    > /dev/null 2>&1 &
pids+=($!)

# 6. Launch guest VM (this stays in foreground)
echo "[*] Launching guest with QEMU=$QEMU ..."
scripts/launch_guest.sh --nocc --vsock 3 # "${LAUNCH_GUEST_SCRIPT_ARGS[@]}"

