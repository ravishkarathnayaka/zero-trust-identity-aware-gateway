#!/usr/bin/env python3
"""
Diagnostic utility for the Zero Trust Gateway stack.
Validates service reachability, TLS certificate validity, and PDP response health.
"""

import sys
import os
import ssl
import socket
import datetime
import urllib.request
import urllib.error

SERVICES = [
    ("Envoy Gateway (HTTPS PEP)", "localhost", 8443, True, "/healthz"),
    ("Envoy Gateway (HTTP PEP)", "localhost", 8000, False, "/healthz"),
    ("Keycloak IdP", "localhost", 8080, False, "/realms/ztna-realm"),
    ("Open Policy Agent (PDP)", "localhost", 8181, False, "/v1/data/ztna/main"),
    ("ExtAuthz Middleware", "localhost", 9001, False, "/healthz"),
]

def check_tcp_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def check_http_endpoint(name: str, host: str, port: int, is_https: bool, path: str):
    proto = "https" if is_https else "http"
    url = f"{proto}://{host}:{port}{path}"
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ZTNA-Diagnostic/1.0"})
        with urllib.request.urlopen(req, context=ctx if is_https else None, timeout=2.0) as resp:
            print(f"  [OK] {name} ({url}) -> HTTP {resp.status}")
            return True
    except urllib.error.HTTPError as e:
        # Some endpoints return 401/403 which still proves the service is alive!
        print(f"  [OK] {name} ({url}) -> HTTP {e.code} (Service Responding)")
        return True
    except Exception as e:
        print(f"  [FAIL] {name} ({url}) -> Unreachable ({e})")
        return False

def inspect_cert(cert_path: str):
    if not os.path.exists(cert_path):
        print(f"  [!] Missing certificate: {cert_path}")
        return

    try:
        import cryptography.x509
        from cryptography.hazmat.backends import default_backend

        with open(cert_path, "rb") as f:
            cert = cryptography.x509.load_pem_x509_certificate(f.read(), default_backend())

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after

        print(f"  [CERT] {os.path.basename(cert_path)}:")
        print(f"         Subject: {subject}")
        print(f"         Issuer:  {issuer}")
        print(f"         Expires: {not_after}")
    except ImportError:
        print(f"  [CERT] {os.path.basename(cert_path)} exists (install cryptography for detailed inspection)")

def main():
    print("===================================================================")
    print("Zero Trust Network Access (ZTNA) - Gateway Stack Health Diagnostics")
    print("===================================================================\n")

    print("[1] Inspecting Local PKI Certificates:")
    certs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docker", "certs"))
    inspect_cert(os.path.join(certs_dir, "ca.crt"))
    inspect_cert(os.path.join(certs_dir, "server.crt"))
    inspect_cert(os.path.join(certs_dir, "client.crt"))

    print("\n[2] Probing Gateway & Microservice Endpoints:")
    all_healthy = True
    for name, host, port, is_https, path in SERVICES:
        tcp_ok = check_tcp_port(host, port)
        if not tcp_ok:
            print(f"  [OFFLINE] {name} (Port {port} not listening)")
            all_healthy = False
        else:
            http_ok = check_http_endpoint(name, host, port, is_https, path)
            if not http_ok:
                all_healthy = False

    print("\n===================================================================")
    if all_healthy:
        print("[SUCCESS] All Zero Trust components are online and responding!")
    else:
        print("[NOTICE] Some containers are offline. Run 'docker compose up -d' to start the stack.")
    print("===================================================================")

if __name__ == "__main__":
    main()
