"""
Protected Developer Portal Microservice.
Strictly isolated within the ZTNA internal network.
Requires 'engineering' role and compliant device posture.
"""

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
import datetime
import uvicorn

app = FastAPI(
    title="Engineering Developer Portal API",
    description="Internal Engineering Microservice - NIST SP 800-207 Protected",
    version="1.0.0"
)

REPOSITORIES = [
    {
        "id": "repo-01",
        "name": "zero-trust-identity-aware-gateway",
        "visibility": "INTERNAL",
        "default_branch": "main",
        "build_status": "PASSING",
        "last_commit": "7a77b19",
        "maintainers": ["bob@corp.local"]
    },
    {
        "id": "repo-02",
        "name": "core-ledger-engine",
        "visibility": "RESTRICTED",
        "default_branch": "main",
        "build_status": "PASSING",
        "last_commit": "f9011ab",
        "maintainers": ["alice@corp.local"]
    },
    {
        "id": "repo-03",
        "name": "iam-policy-engine-rego",
        "visibility": "INTERNAL",
        "default_branch": "main",
        "build_status": "PASSING",
        "last_commit": "3c51dd2",
        "maintainers": ["bob@corp.local"]
    }
]

DEPLOYMENTS = [
    {
        "environment": "production",
        "cluster": "k8s-prod-us-east-1",
        "namespace": "gateway",
        "replicas": 3,
        "healthy_replicas": 3,
        "active_version": "v1.4.0"
    },
    {
        "environment": "staging",
        "cluster": "k8s-stage-us-east-1",
        "namespace": "gateway",
        "replicas": 2,
        "healthy_replicas": 2,
        "active_version": "v1.5.0-rc1"
    }
]

@app.get("/healthz", tags=["System"])
def health_check():
    return {
        "status": "healthy",
        "service": "dev_portal",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

@app.get("/api/dev/repositories", tags=["Engineering"])
def list_repositories(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_roles: Optional[str] = Header(None, alias="X-User-Roles"),
    x_auth_decision: Optional[str] = Header(None, alias="X-Auth-Decision")
):
    """
    Returns engineering repositories. Requires identity injected by Envoy.
    """
    return {
        "service": "dev_portal",
        "caller": {
            "user": x_user_id or "UNKNOWN",
            "roles": [r.strip() for r in (x_user_roles or "").split(",") if r.strip()],
            "decision": x_auth_decision or "NONE"
        },
        "repositories_count": len(REPOSITORIES),
        "repositories": REPOSITORIES
    }

@app.get("/api/dev/deployments", tags=["Engineering"])
def list_deployments(
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_user_roles: Optional[str] = Header(None, alias="X-User-Roles")
):
    return {
        "service": "dev_portal",
        "caller": x_user_id or "UNKNOWN",
        "deployments": DEPLOYMENTS
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)
