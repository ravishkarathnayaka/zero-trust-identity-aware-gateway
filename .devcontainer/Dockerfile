FROM mcr.microsoft.com/devcontainers/python:3.11-bookworm

# Install OpenSSL, curl, jq, and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    curl \
    jq \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Open Policy Agent (OPA) CLI
RUN curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static \
    && chmod 755 /usr/local/bin/opa
