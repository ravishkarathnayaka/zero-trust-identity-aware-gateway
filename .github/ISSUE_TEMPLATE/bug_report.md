---
name: Bug Report
about: Create a report to help us improve the ZTNA Gateway
title: '[BUG] '
labels: bug
assignees: ''
---

**Describe the Bug**
A clear and concise description of what the bug is.

**Component Affected**
- [ ] Envoy PEP (`gateway/envoy.yaml`)
- [ ] ExtAuthz Middleware (`gateway/ext_authz_service/`)
- [ ] OPA Rego Policies (`policies/`)
- [ ] Keycloak IdP (`idp/`)
- [ ] Protected Microservice (`services/`)
- [ ] Web Portal (`web/`)

**Steps to Reproduce**
1. Send request with headers '...'
2. Expected response '...'
3. Observed response '...'

**Environment**
- OS: [e.g. Ubuntu 22.04, macOS 14, Windows 11]
- Docker Version: [e.g. 26.0]
- OPA Version: [e.g. 1.0.0]
