#!/bin/bash

set -e
# --- Create output directory --- 
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
OUTPUT_DIR="$(realpath "$SCRIPT_DIR/../certificates")"
mkdir -p "$OUTPUT_DIR" 

# --- Configs --- 
ROOT_CA_NAME="Test Root CA" 
ROOT_CA_COUNTRY="IT" 
ROOT_CA_ORG="TestCA" 
ROOT_CA_VALIDITY_DAYS=3650 
ROOT_CA_STATE="Italy" 
ROOT_CA_LOCALITY="Pisa"
SERVER_NAME="localhost" 
SERVER_IP="127.0.0.1"
SERVER_COUNTRY="IT" 
SERVER_ORG="TestServer" 
SERVER_STATE="Italy"
SERVER_LOCALITY="Pisa"
SERVER_VALIDITY_DAYS=365
CLIENT_NAME="client"
CLIENT_VALIDITY_DAYS=365

# File output 
CA_KEY="$OUTPUT_DIR/ca.key" 
CA_CERT="$OUTPUT_DIR/ca.crt" 
CA_DER="$OUTPUT_DIR/ca.der" 
SERVER_KEY="$OUTPUT_DIR/server.key" 
SERVER_CSR="$OUTPUT_DIR/server.csr" 
SERVER_CERT="$OUTPUT_DIR/server.crt" 
SERVER_EXT="$OUTPUT_DIR/server_ext.cnf"
CLIENT_EXT="$OUTPUT_DIR/client_ext.cnf"
CLIENT_KEY="$OUTPUT_DIR/client.key"
CLIENT_CSR="$OUTPUT_DIR/client.csr"
CLIENT_CERT="$OUTPUT_DIR/client.crt"
CLIENT_DER="$OUTPUT_DIR/client.der"

# Temporary files
CLIENT_EXT_FILE=$(mktemp)
CLIENT_KEY_TMP=$(mktemp)

# --- 1. Create CA private key --- 
echo "Creating CA private key..." 
openssl genrsa -out "$CA_KEY" 4096 

# --- 2. Create CA root certificate (self-signed) --- 
echo "Creating CA root certificate..." 
openssl req -x509 -new -nodes \
    -key "$CA_KEY" \
    -sha256 \
    -days $ROOT_CA_VALIDITY_DAYS \
    -out "$CA_CERT" \
    -subj "/C=$ROOT_CA_COUNTRY/ST=$ROOT_CA_STATE/L=$ROOT_CA_LOCALITY/O=$ROOT_CA_ORG/CN=$ROOT_CA_NAME"   

# --- 3. Convert CA certificate to DER for client ---
echo "Converting CA certificate to DER format..." 
openssl x509 \
    -in "$CA_CERT" \
    -outform der \
    -out "$CA_DER"

# --- 4. Create server private key --- 
echo "Creating server private key..."
openssl genrsa \
    -out "$SERVER_KEY" \
    2048

# --- 5. Create SAN extensions file ---
echo "Creating SAN extensions file..."
cat > "$SERVER_EXT" <<EOL
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_NAME
IP.1 = $SERVER_IP
EOL

# --- 6. Create server CSR (with SAN) ---
echo "Creating server CSR..."
openssl req -new \
    -key "$SERVER_KEY" \
    -out "$SERVER_CSR" \
    -subj "/C=$SERVER_COUNTRY/ST=$SERVER_STATE/L=$SERVER_LOCALITY/O=$SERVER_ORG/CN=$SERVER_NAME" \
    -config "$SERVER_EXT"

# --- 7. Sign server certificate with CA --- 
echo "Signing server certificate with CA..." 
openssl x509 -req \
    -in "$SERVER_CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$SERVER_CERT" \
    -days $SERVER_VALIDITY_DAYS \
    -sha256 \
    -extfile "$SERVER_EXT"


# --- 8. Generate client certificate ---
echo "Generating client certificate..."
echo "Generating client private key..."
openssl ecparam -name prime256v1 -genkey -noout -out "$CLIENT_KEY"

openssl pkcs8 -topk8 \
    -inform PEM -outform PEM \
    -in "$CLIENT_KEY" \
    -out "$CLIENT_KEY_TMP" \
    -nocrypt

mv "$CLIENT_KEY_TMP" "$CLIENT_KEY"

# --- 9. Create client CSR ---
echo "Creating client CSR..."
openssl req -new \
    -key "$CLIENT_KEY" \
    -out "$CLIENT_CSR" \
    -subj "/CN=$CLIENT_NAME"

# --- 10. Create client extensions file ---
echo "Creating client extensions file..."
cat > "$CLIENT_EXT_FILE" <<EOF
[client_ext]
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

# --- 11. Sign client certificate with CA ---
echo "Signing client certificate with CA..."
openssl x509 -req \
    -in "$CLIENT_CSR" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$CLIENT_CERT" \
    -days "$CLIENT_VALIDITY_DAYS" \
    -sha256 \
    -extfile "$CLIENT_EXT_FILE" \
    -extensions client_ext

# --- 12. Convert client certificate to DER ---
echo "Converting client certificate to DER format..."
openssl x509 \
    -in "$CLIENT_CERT" \
    -outform DER \
    -out "$CLIENT_DER"

# --- 13. Cleanup temporary files ---
rm -f "$SERVER_CSR" "$SERVER_EXT" "$CLIENT_CSR" "$CLIENT_EXT_FILE" "$CA_CERT.srl"

echo "=== Operation completed ==="
echo "CA certificate: $CA_CERT"
echo "CA certificate (DER): $CA_DER"
echo "Server certificate: $SERVER_CERT"
echo "Server private key: $SERVER_KEY"
echo "Client certificate: $CLIENT_CERT"
echo "Client certificate (DER): $CLIENT_DER"
echo "Client private key: $CLIENT_KEY"