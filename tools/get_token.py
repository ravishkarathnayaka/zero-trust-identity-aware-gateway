#!/usr/bin/env python3
"""
CLI Utility to obtain and inspect OIDC JWT tokens from Keycloak.
Part of the NIST SP 800-207 Zero Trust Gateway testbed.
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
import base64
import time

DEFAULT_KEYCLOAK_URL = "http://localhost:8080"
DEFAULT_REALM = "ztna-realm"
DEFAULT_CLIENT_ID = "ztna-gateway"
DEFAULT_CLIENT_SECRET = "ztna-gateway-secret-dev-key"

PRESET_USERS = {
    "alice": ("alice", "password123", "Finance Lead (finance-admin)"),
    "bob": ("bob", "password123", "Staff Engineer (engineering)"),
    "charlie": ("charlie", "password123", "Compliance Auditor (auditor)"),
    "eve": ("eve", "password123", "Guest User (unprivileged)")
}

def decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    # Add padding if missing
    padding = 4 - (len(payload_b64) % 4)
    if padding != 4:
        payload_b64 += "=" * padding
    try:
        decoded_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        return json.loads(decoded_bytes.decode("utf-8"))
    except Exception:
        return {}

def obtain_token(base_url: str, realm: str, client_id: str, client_secret: str, username: str, password: str) -> dict:
    token_url = f"{base_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "password",
        "username": username,
        "password": password
    }).encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"[!] Error fetching token (HTTP {e.code}): {err_body}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Network error contacting Keycloak: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Obtain and decode Keycloak OIDC JWT tokens for ZTNA testing.")
    parser.add_argument("--user", choices=["alice", "bob", "charlie", "eve"], default="alice", help="Preconfigured user persona")
    parser.add_argument("--username", help="Custom username")
    parser.add_argument("--password", help="Custom password")
    parser.add_argument("--url", default=DEFAULT_KEYCLOAK_URL, help="Keycloak Base URL")
    parser.add_argument("--realm", default=DEFAULT_REALM, help="Keycloak Realm")
    parser.add_argument("--raw", action="store_true", help="Print raw access_token only")
    parser.add_argument("--inspect", action="store_true", help="Print decoded token payload claims")

    args = parser.parse_args()

    if args.username and args.password:
        username = args.username
        password = args.password
    else:
        username, password, desc = PRESET_USERS[args.user]
        if not args.raw:
            print(f"[*] Requesting token for persona: {args.user} ({desc})...", file=sys.stderr)

    token_data = obtain_token(args.url, args.realm, DEFAULT_CLIENT_ID, DEFAULT_CLIENT_SECRET, username, password)
    access_token = token_data.get("access_token", "")

    if args.raw:
        print(access_token)
        return

    print("\n=======================================================")
    print("OIDC Access Token Issued Successfully!")
    print("=======================================================")
    print(f"Expires in: {token_data.get('expires_in', 0)} seconds")
    print(f"Token Type: {token_data.get('token_type', 'Bearer')}\n")

    if args.inspect:
        payload = decode_jwt_payload(access_token)
        print("Decoded Claims:")
        print(json.dumps(payload, indent=2))
        print("=======================================================\n")

    print(f"Raw Token:\n{access_token}")

if __name__ == "__main__":
    main()
