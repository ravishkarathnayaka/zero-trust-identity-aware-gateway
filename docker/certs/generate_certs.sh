#!/usr/bin/env bash
# ==============================================================================
# Generate Internal PKI and TLS Certificates for Zero Trust Gateway
# Creates Root CA, Envoy Server Certificate, and Client Device mTLS Certificate
# ==============================================================================
set -euo pipefail

CERTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${CERTS_DIR}"

echo "[+] Generating Zero Trust PKI in: ${CERTS_DIR}"

# 1. Generate Root Certificate Authority (CA)
if [ ! -f "ca.key" ]; then
    echo "[*] Creating Root CA Private Key..."
    openssl genrsa -out ca.key 4096
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
        -out ca.crt \
        -subj "/C=US/ST=Security/L=Enterprise/O=ZeroTrustCorp/OU=Cybersecurity/CN=ZeroTrust-Root-CA"
    echo "[✓] Root CA created: ca.crt"
else
    echo "[!] Existing Root CA found. Skipping CA generation."
fi

# 2. Generate Server Certificate for Envoy Gateway (PEP)
echo "[*] Creating Envoy PEP Server Key & CSR..."
openssl genrsa -out server.key 2048

cat > server_ext.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Security
L = Enterprise
O = ZeroTrustCorp
OU = Gateway
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = envoy
DNS.3 = gateway
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

openssl req -new -key server.key -out server.csr -config server_ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extfile server_ext.cnf -extensions v3_req
echo "[✓] Envoy Server Certificate created: server.crt"

# 3. Generate Sample Client Certificate (mTLS / Device Posture Verification)
echo "[*] Creating Client Corporate Device Certificate..."
openssl genrsa -out client.key 2048

cat > client_ext.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Security
L = Enterprise
O = ZeroTrustCorp
OU = ManagedDevices
CN = alice-corporate-laptop

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl req -new -key client.key -out client.csr -config client_ext.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -sha256 -extfile client_ext.cnf -extensions v3_req
echo "[✓] Client Device Certificate created: client.crt"

# Clean up CSR and config temp files
rm -f server.csr client.csr server_ext.cnf client_ext.cnf

# Restrict permissions
chmod 600 *.key || true
chmod 644 *.crt || true

echo "==================================================================="
echo "Zero Trust PKI Generation Complete!"
echo "Files created:"
echo " - ca.crt / ca.key        : Root Certificate Authority"
echo " - server.crt / server.key: Envoy Gateway TLS Certificate"
echo " - client.crt / client.key: Client Device Certificate"
echo "==================================================================="
