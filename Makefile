# ==============================================================================
# Makefile: Zero Trust Network Access (ZTNA) Gateway Development & Operations
# ==============================================================================

SHELL := /bin/bash
.PHONY: help certs up down restart logs ps test test-opa test-python lint token-alice token-bob clean

help: ## Display list of available Makefile targets
	@echo "Zero Trust Network Access (ZTNA) Gateway - Development Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

certs: ## Generate internal Root CA, Envoy Server TLS, and client certificates
	@echo "[+] Generating PKI and TLS certificates..."
	@cd docker && chmod +x certs/generate_certs.sh && ./certs/generate_certs.sh

up: certs ## Build and start the multi-container Docker Compose stack in detached mode
	@echo "[+] Starting Zero Trust stack..."
	@cd docker && docker compose up -d --build

down: ## Stop and remove all running containers and networks
	@echo "[-] Stopping Zero Trust stack..."
	@cd docker && docker compose down

restart: down up ## Restart the complete Docker Compose stack

logs: ## Tail aggregated logs from all gateway and microservice containers
	@cd docker && docker compose logs -f

ps: ## Check status and health of all containers
	@cd docker && docker compose ps

test-opa: ## Execute Open Policy Agent Rego v1 unit tests
	@echo "[*] Running OPA policy tests..."
	@if command -v opa >/dev/null 2>&1; then \
		opa test policies/ -v; \
	else \
		docker run --rm -v "$$(pwd)/policies:/policies" openpolicyagent/opa:latest test /policies -v; \
	fi

test-python: ## Run pytest unit and integration test suite
	@echo "[*] Running Python tests..."
	@python -m pytest tests/ -v

test: test-opa test-python ## Run all automated tests (OPA + Python)

lint: ## Check Python codebase with flake8
	@echo "[*] Linting codebase..."
	@python -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

token-alice: ## Request OIDC access token for Alice (Finance Admin)
	@python tools/get_token.py --user alice

token-bob: ## Request OIDC access token for Bob (Staff Engineer)
	@python tools/get_token.py --user bob

token-charlie: ## Request OIDC access token for Charlie (Auditor)
	@python tools/get_token.py --user charlie

clean: ## Clean up local caches, certificates, and test artifacts
	@echo "[*] Cleaning up temporary build and test files..."
	@rm -rf .pytest_cache htmlcov .coverage
	@rm -f docker/certs/*.crt docker/certs/*.key docker/certs/*.csr docker/certs/*.srl
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
