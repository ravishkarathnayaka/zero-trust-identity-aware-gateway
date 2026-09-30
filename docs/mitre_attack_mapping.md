# MITRE ATT&CK® Threat Model & NIST SP 800-207 Mitigation Matrix

This document maps the **Zero Trust Network Access (ZTNA) & Identity-Aware Microsegmentation Gateway** against real-world adversarial tactics, techniques, and procedures (TTPs) from the **MITRE ATT&CK® Enterprise Matrix**.

---

## 1. Threat Mitigation Matrix

| MITRE ATT&CK ID | Technique Name | Traditional Perimeter VPN Vulnerability | ZTNA Gateway Mitigation (NIST SP 800-207) | Enforcing Component |
| :--- | :--- | :--- | :--- | :--- |
| **T1133** | **External Remote Services** | Legacy VPN gateways expose flat subnets to external attackers with static passwords or weak session tokens. | Ingress terminates exclusively at Envoy PEP (Port 8443) with mandatory OIDC JWT authentication and device posture telemetry. | Envoy PEP + Keycloak |
| **T1021** | **Remote Services (Lateral Movement)** | Once past the VPN perimeter, attackers can pivot to internal database, finance, and engineering services. | **Microsegmentation**: `finance_api` and `dev_portal` reside in an isolated Docker network without exposed host ports; lateral hops between microservices are blocked. | Docker Bridge Isolation + Envoy PEP |
| **T1078** | **Valid Accounts (Credential Compromise)** | Stolen valid employee credentials grant unimpeded access to sensitive endpoints regardless of device security. | **Device Posture Verification**: Valid credentials are conditionally denied if the client device lacks disk encryption, runs an untrusted OS, or is unmanaged. | OPA (`posture.rego`) |
| **T1046** | **Network Service Discovery** | Attackers perform internal port scans (`nmap`) to map private infrastructure across the VPN subnet. | Protected services are not routable from the host or other subnets; scanning internal ports returns closed/filtered. | Docker Transit Network |
| **T1098** | **Account Manipulation / Privilege Escalation** | Attackers compromise a developer account and attempt unauthorized financial ledger access or wire payouts. | **Granular RBAC**: OPA policy checks (`rbac.rego`) strictly restrict `/api/finance/*` mutations to `finance-admin`. Engineering accounts receive instant HTTP 403. | OPA (`rbac.rego`) |
| **T1071** | **Application Layer Protocol (Command & Control)** | C2 traffic blends into allowed corporate network connections without inspection. | Policy Enforcement Point inspects all HTTP requests; unauthenticated or malformed requests are terminated at the perimeter proxy. | Envoy PEP + ExtAuthz |

---

## 2. NIST SP 800-207 Core Tenets vs Adversary Capabilities

```
Attacker Vectors                          ZTNA Defensive Enforcements
================                         ===========================
Stolen Credentials ────────────────────► Keycloak (OIDC RS256 Tokens) + Multi-Factor Claims
Unencrypted/Compromised Laptop ────────► OPA Posture Rule (posture.rego rejects unencrypted disk)
Lateral Movement to Finance API ───────► Envoy PEP (Microsegmentation restricts /api/finance/*)
Brute-force / Replay Attempts ─────────► ExtAuthz Middleware (Strict JWT lifespan & fail-closed)
Tampered Upstream Identity ────────────► Envoy PEP Injects X-User-Id directly into data plane
```

---

## 3. Defense-in-Depth Verification Scenarios

1. **Scenario 1: Compromised Engineer Laptop Targeting Finance**:
   - Attacker obtains valid token for `bob` (Engineering).
   - Attempts: `GET /api/finance/ledger`.
   - Result: Terminated with **HTTP 403 Forbidden** (Missing required `finance-admin` role).

2. **Scenario 2: Finance Executive Using Personal / Unencrypted Laptop**:
   - User `alice` authenticates successfully via Keycloak.
   - Device posture telemetry reveals `encrypted=false`.
   - Result: Terminated with **HTTP 403 Forbidden** ("Disk encryption is disabled").

3. **Scenario 3: Zero Trust Fail-Closed Mechanics**:
   - If the Policy Engine (OPA) or ExtAuthz service is taken offline, Envoy PEP's `failure_mode_allow: false` setting ensures **all** ingress requests are rejected rather than allowed by default.
