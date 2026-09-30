# Security Policy

## Reporting a Vulnerability

The Zero Trust Network Access (ZTNA) & Identity-Aware Microsegmentation Gateway project takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose findings.

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

### Vulnerability Reporting Process

If you discover a security vulnerability (such as a policy bypass, token forgery vector, or unauthenticated route exposure):

1. **Do NOT open a public GitHub issue.**
2. Send an email to the repository maintainer with:
   - Detailed description of the issue
   - Reproduction steps or proof of concept (PoC)
   - Affected component (Envoy PEP, OPA Policy, ExtAuthz Service, or Keycloak config)
   - Potential impact assessment
3. You will receive an initial response within **24 hours**.
4. We aim to validate and provide a remediation within **72 hours** of confirmation.

### Scope

The following components are in scope for security evaluations:
- **Envoy Proxy Gateway Configuration** (`gateway/envoy.yaml`)
- **ExtAuthz Policy Administrator Service** (`gateway/ext_authz_service/`)
- **Open Policy Agent Rego Rules** (`policies/*.rego`)
- **Keycloak OIDC Realm Definitions** (`idp/*.json`)
- **Docker Network Isolation & PKI Scripts** (`docker/`)

### Automated Security Scans

This repository continuously executes automated security scanning in CI:
- **Bandit**: Static Application Security Testing (SAST) for Python
- **Gitleaks**: Secrets and credential leakage detection
- **Trivy**: Container image and configuration vulnerability analysis
