"""
Unit Tests for ZTNA Gateway ExtAuthz Middleware & Rego Decision Processing.
Validates JWT extraction, device posture parsing, OPA input shaping, and response headers.
"""

import sys
import os
import time
import json
import pytest
from unittest.mock import patch, AsyncMock
import jwt

# Add gateway/ext_authz_service to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway", "ext_authz_service")))

from main import (
    app,
    parse_device_posture,
    extract_and_validate_jwt,
    extract_identity,
    evaluate_opa_policy
)
from fastapi.testclient import TestClient

client = TestClient(app)

SECRET_KEY = "test-secret-key-ztna-gateway-32bytes-secure!"

def create_mock_jwt(user="alice", roles=None, email="alice@corp.local", expired=False):
    """Helper to generate JWT tokens for testing."""
    if roles is None:
        roles = ["finance-admin"]

    now = int(time.time())
    payload = {
        "sub": f"user-{user}",
        "preferred_username": user,
        "email": email,
        "iat": now,
        "exp": now - 100 if expired else now + 3600,
        "realm_access": {
            "roles": roles
        }
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


# ==============================================================================
# 1. Device Posture Parser Tests
# ==============================================================================
class TestDevicePostureParser:
    def test_default_posture_when_empty(self):
        posture = parse_device_posture(None)
        assert posture["encrypted"] is False
        assert posture["os"] == "unknown"
        assert posture["patch_level"] == "outdated"
        assert posture["corporate_managed"] is False

    def test_comma_separated_posture_parsing(self):
        header = "encrypted=true,os=linux,patch_level=current,corporate_managed=true"
        posture = parse_device_posture(header)
        assert posture["encrypted"] is True
        assert posture["os"] == "linux"
        assert posture["patch_level"] == "current"
        assert posture["corporate_managed"] is True

    def test_json_posture_parsing(self):
        header = json.dumps({
            "encrypted": True,
            "os": "darwin",
            "patch_level": "current",
            "corporate_managed": False
        })
        posture = parse_device_posture(header)
        assert posture["encrypted"] is True
        assert posture["os"] == "darwin"
        assert posture["patch_level"] == "current"
        assert posture["corporate_managed"] is False

    def test_unencrypted_posture_parsing(self):
        header = "encrypted=false,os=windows_11,patch_level=outdated,corporate_managed=true"
        posture = parse_device_posture(header)
        assert posture["encrypted"] is False
        assert posture["patch_level"] == "outdated"


# ==============================================================================
# 2. JWT Extraction & Identity Tests
# ==============================================================================
class TestJWTAndIdentityExtraction:
    def test_missing_auth_header(self):
        is_auth, claims, err = extract_and_validate_jwt(None)
        assert is_auth is False
        assert "Missing" in err

    def test_malformed_auth_header(self):
        is_auth, claims, err = extract_and_validate_jwt("Basic username:pass")
        assert is_auth is False
        assert "Malformed" in err or "Missing" in err

    def test_expired_token(self):
        expired_token = create_mock_jwt(expired=True)
        is_auth, claims, err = extract_and_validate_jwt(f"Bearer {expired_token}")
        assert is_auth is False
        assert "expired" in err.lower()

    def test_valid_token_extracts_identity(self):
        token = create_mock_jwt(user="bob", roles=["engineering"], email="bob@corp.local")
        is_auth, claims, err = extract_and_validate_jwt(f"Bearer {token}")
        assert is_auth is True
        assert err is None

        identity = extract_identity(claims, is_auth)
        assert identity["user"] == "bob"
        assert identity["email"] == "bob@corp.local"
        assert "engineering" in identity["roles"]
        assert identity["authenticated"] is True


# ==============================================================================
# 3. ExtAuthz Middleware Endpoint Verification
# ==============================================================================
class TestExtAuthzEndpoints:
    def test_healthz_endpoint(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ext_authz_middleware"

    def test_unauthenticated_protected_request_returns_401(self):
        resp = client.get("/api/finance/ledger")
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers
        data = resp.json()
        assert data["status"] == "UNAUTHORIZED"
        assert data["error"] == "AuthenticationRequired"

    @patch("main.evaluate_opa_policy")
    def test_authorized_request_returns_200_with_downstream_headers(self, mock_opa):
        # Mock OPA returning allowed
        mock_opa.return_value = {
            "allowed": True,
            "violations": [],
            "headers": {
                "X-User-Id": "alice",
                "X-User-Roles": "finance-admin",
                "X-Auth-Decision": "ALLOWED",
                "X-ZTNA-Policy": "NIST-SP-800-207"
            }
        }

        token = create_mock_jwt(user="alice", roles=["finance-admin"])
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=linux,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }

        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-User-Id") == "alice"
        assert resp.headers.get("X-User-Roles") == "finance-admin"
        assert resp.headers.get("X-Auth-Decision") == "ALLOWED"

    @patch("main.evaluate_opa_policy")
    def test_denied_request_returns_403_with_policy_violations(self, mock_opa):
        # Mock OPA returning denied due to device posture
        mock_opa.return_value = {
            "allowed": False,
            "violations": ["Device Posture Violation: Disk encryption is disabled"]
        }

        token = create_mock_jwt(user="alice", roles=["finance-admin"])
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=false,os=linux,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }

        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 403
        data = resp.json()
        assert data["status"] == "DENIED"
        assert "Device Posture Violation: Disk encryption is disabled" in data["policy_violations"]
