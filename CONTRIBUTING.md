# Contributing to ZTNA Gateway

Thank you for your interest in contributing to the **Zero Trust Network Access (ZTNA) & Identity-Aware Microsegmentation Gateway**!

## Development Guidelines

### 1. Prerequisites
- Python 3.11+
- Docker Desktop & Docker Compose
- Open Policy Agent (OPA) CLI (optional, can run via Docker)
- OpenSSL CLI

### 2. Setting Up Your Environment
```bash
# Clone the repository
git clone https://github.com/ravishkarathnayaka/zero-trust-identity-aware-gateway.git
cd zero-trust-identity-aware-gateway

# Install Python test dependencies
pip install -r gateway/ext_authz_service/requirements.txt
pip install pytest pytest-cov flake8
```

### 3. Making Changes
- **Branching Strategy**: Create a feature branch from `main`:
  ```bash
  git checkout -b feat/your-feature-name
  ```
- **Commit Conventions**: Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- **Rego Policies**: Any modifications to `.rego` files must be accompanied by corresponding unit tests in `policies/tests/`.

### 4. Running Verification
Before submitting a PR, verify all tests pass:
```bash
# Run OPA tests
opa test policies/ -v

# Run Python unit & integration tests
python -m pytest tests/ -v

# Run linter
python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

### 5. Pull Request Checklist
- [ ] New policy rules have test coverage in `policies/tests/`.
- [ ] All 21+ Python tests pass cleanly without regressions.
- [ ] No private keys or secrets are committed.
- [ ] Documentation updated to reflect changes.
