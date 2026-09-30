#!/usr/bin/env python3
"""
Interactive CLI Tester for Zero Trust Gateway.
Provides an interactive menu for testing identities, postures, and endpoints.
"""

import sys
import os
import json
import ssl
import urllib.request
import urllib.error

# ANSI terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

PERSONAS = {
    "1": ("Alice", "finance-admin", "alice@corp.local"),
    "2": ("Bob", "engineering", "bob@corp.local"),
    "3": ("Charlie", "auditor", "charlie@corp.local"),
    "4": ("Eve", "user", "eve@corp.local"),
    "5": ("Anonymous (No Token)", None, "")
}

ENDPOINTS = {
    "1": ("GET", "/api/finance/ledger", "Finance General Ledger (High Sensitivity)"),
    "2": ("POST", "/api/finance/payout", "Finance Wire Transfer (High Sensitivity Mutation)"),
    "3": ("GET", "/api/dev/repositories", "Engineering Repositories (Medium Sensitivity)"),
    "4": ("GET", "/api/dev/deployments", "Cluster Deployments (Medium Sensitivity)"),
    "5": ("GET", "/healthz", "Gateway Health Check (Public)")
}

def print_banner():
    print(f"{CYAN}{BOLD}===================================================================")
    print("Zero Trust Network Access (ZTNA) - Interactive Terminal Tester")
    print("NIST SP 800-207 Policy Enforcement Simulation")
    print(f"==================================================================={RESET}\n")

def run_test():
    print_banner()

    # Step 1: Select Persona
    print(f"{BOLD}[1] Select Identity Persona:{RESET}")
    for key, (name, role, email) in PERSONAS.items():
        role_str = f"({role})" if role else ""
        print(f"  [{key}] {name} {role_str}")
    user_choice = input(f"{YELLOW}Select persona [1-5] (default 1): {RESET}").strip() or "1"
    name, role, email = PERSONAS.get(user_choice, PERSONAS["1"])

    # Step 2: Posture Telemetry
    print(f"\n{BOLD}[2] Configure Device Posture:{RESET}")
    enc_in = input(f"  Enable Disk Encryption? [Y/n]: ").strip().lower()
    is_encrypted = False if enc_in == "n" else True

    patch_in = input(f"  OS Patch Level (1: current, 2: outdated) [1/2] (default 1): ").strip()
    patch_level = "outdated" if patch_in == "2" else "current"

    mdm_in = input(f"  Corporate MDM Managed? [Y/n]: ").strip().lower()
    is_managed = False if mdm_in == "n" else True

    posture_str = f"encrypted={'true' if is_encrypted else 'false'},os=linux,patch_level={patch_level},corporate_managed={'true' if is_managed else 'false'}"

    # Step 3: Target Endpoint
    print(f"\n{BOLD}[3] Select Target Microservice:{RESET}")
    for key, (method, path, desc) in ENDPOINTS.items():
        print(f"  [{key}] {method} {path} - {desc}")
    endpoint_choice = input(f"{YELLOW}Select endpoint [1-5] (default 1): {RESET}").strip() or "1"
    method, path, desc = ENDPOINTS.get(endpoint_choice, ENDPOINTS["1"])

    print(f"\n{CYAN}[*] Evaluating Request:{RESET}")
    print(f"    Subject:  {name} (Role: {role or 'None'})")
    print(f"    Posture:  {posture_str}")
    print(f"    Target:   {method} {path}")

    # Build cURL preview
    auth_header = f"Authorization: Bearer <TOKEN_FOR_{name.upper()}>" if role else ""
    print(f"\n{BOLD}Equivalent Command:{RESET}")
    print(f"curl -k -i -X {method} \"https://localhost:8443{path}\" \\")
    if auth_header:
        print(f"  -H \"{auth_header}\" \\")
    print(f"  -H \"X-Device-Posture: {posture_str}\"\n")

    # Send Request to Envoy PEP (if reachable)
    gateway_url = f"https://localhost:8443{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = {
        "X-Device-Posture": posture_str,
        "User-Agent": "ZTNA-Interactive-Tester/1.0"
    }

    try:
        req = urllib.request.Request(gateway_url, headers=headers, method=method)
        with urllib.request.urlopen(req, context=ctx, timeout=3.0) as resp:
            print(f"{GREEN}{BOLD}[RESULT: ALLOWED] HTTP {resp.status} OK{RESET}")
            body = resp.read().decode("utf-8")
            print(f"Response Payload:\n{body}")
    except urllib.error.HTTPError as e:
        status_code = e.code
        body = e.read().decode("utf-8")
        if status_code in (401, 403):
            print(f"{RED}{BOLD}[RESULT: BLOCKED BY ZERO TRUST POLICY] HTTP {status_code}{RESET}")
        else:
            print(f"{YELLOW}[HTTP {status_code}] Response:{RESET}")
        print(f"Details:\n{body}")
    except Exception as e:
        print(f"{YELLOW}[NOTICE] Envoy gateway at {gateway_url} is not currently running ({e}).")
        print(f"To spin up the multi-container stack, run: docker compose up -d{RESET}")

if __name__ == "__main__":
    run_test()
