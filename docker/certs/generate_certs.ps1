# ==============================================================================
# Generate Internal PKI and TLS Certificates for Zero Trust Gateway (PowerShell)
# Creates Root CA, Envoy Server Certificate, and Client Device mTLS Certificate
# ==============================================================================
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir

try {
    Write-Host "[+] Generating Zero Trust PKI in: $scriptDir" -ForegroundColor Cyan

    # 1. Generate Root Certificate Authority (CA)
    if (-not (Test-Path "ca.key")) {
        Write-Host "[*] Creating Root CA Private Key and Certificate..." -ForegroundColor Yellow
        openssl genrsa -out ca.key 4096
        openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 `
            -out ca.crt `
            -subj "/C=US/ST=Security/L=Enterprise/O=ZeroTrustCorp/OU=Cybersecurity/CN=ZeroTrust-Root-CA"
        Write-Host "[OK] Root CA created: ca.crt" -ForegroundColor Green
    } else {
        Write-Host "[!] Existing Root CA found. Skipping CA generation." -ForegroundColor Gray
    }

    # 2. Server Certificate Configuration
    $serverLines = @(
        "[req]",
        "distinguished_name = req_distinguished_name",
        "req_extensions = v3_req",
        "prompt = no",
        "",
        "[req_distinguished_name]",
        "C = US",
        "ST = Security",
        "L = Enterprise",
        "O = ZeroTrustCorp",
        "OU = Gateway",
        "CN = localhost",
        "",
        "[v3_req]",
        "keyUsage = keyEncipherment, dataEncipherment",
        "extendedKeyUsage = serverAuth",
        "subjectAltName = @alt_names",
        "",
        "[alt_names]",
        "DNS.1 = localhost",
        "DNS.2 = envoy",
        "DNS.3 = gateway",
        "IP.1 = 127.0.0.1",
        "IP.2 = 0.0.0.0"
    )
    Set-Content -Path (Join-Path $scriptDir "server_ext.cnf") -Value $serverLines -Encoding ASCII

    Write-Host "[*] Creating Envoy PEP Server Key and Certificate..." -ForegroundColor Yellow
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr -config server_ext.cnf
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial `
        -out server.crt -days 365 -sha256 -extfile server_ext.cnf -extensions v3_req
    Write-Host "[OK] Envoy Server Certificate created: server.crt" -ForegroundColor Green

    # 3. Client Certificate Configuration
    $clientLines = @(
        "[req]",
        "distinguished_name = req_distinguished_name",
        "req_extensions = v3_req",
        "prompt = no",
        "",
        "[req_distinguished_name]",
        "C = US",
        "ST = Security",
        "L = Enterprise",
        "O = ZeroTrustCorp",
        "OU = ManagedDevices",
        "CN = alice-corporate-laptop",
        "",
        "[v3_req]",
        "keyUsage = digitalSignature, keyEncipherment",
        "extendedKeyUsage = clientAuth"
    )
    Set-Content -Path (Join-Path $scriptDir "client_ext.cnf") -Value $clientLines -Encoding ASCII

    Write-Host "[*] Creating Client Corporate Device Certificate..." -ForegroundColor Yellow
    openssl genrsa -out client.key 2048
    openssl req -new -key client.key -out client.csr -config client_ext.cnf
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial `
        -out client.crt -days 365 -sha256 -extfile client_ext.cnf -extensions v3_req
    Write-Host "[OK] Client Device Certificate created: client.crt" -ForegroundColor Green

    # Clean up temp files
    Remove-Item -Force -ErrorAction SilentlyContinue server.csr, client.csr, server_ext.cnf, client_ext.cnf

    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "Zero Trust PKI Generation Complete!" -ForegroundColor Green
    Write-Host "Files created: ca.crt, ca.key, server.crt, server.key, client.crt, client.key" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Cyan
}
finally {
    Pop-Location
}
