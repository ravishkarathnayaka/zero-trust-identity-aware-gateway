"""
End-to-End Authorization Flows Integration Test Suite.
Verifies NIST SP 800-207 Zero Trust decision logic across varied identity and device postures:
1. Valid Finance Token + Compliant Device Posture -> 200 OK.
2. Valid Finance Token + Non-Compliant Device (Unencrypted Disk) -> 403 Forbidden.
3. Valid Finance Token + Outdated Patch Level -> 403 Forbidden.
4. Valid Engineering Token -> Finance API -> 403 Forbidden (RBAC violation).
5. Valid Engineering Token + Compliant Device -> Dev Portal -> 200 OK.
6. Auditor Token -> Finance API Read -> 200 OK.
7. Auditor Token -> Finance API Write (Payout) -> 403 Forbidden.
8. Unauthenticated Request -> Protected Endpoint -> 401 Unauthorized.
9. Expired Token -> 401 Unauthorized.
"""

import sys
import os
import time
import pytest
from unittest.mock import patch
import jwt

# Add paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "gateway", "ext_authz_service")))

from main import app
from fastapi.testclient import TestClient

client = TestClient(app)

SECRET_KEY = "test-secret-key-integration-ztna-32bytes-secure!"

def generate_test_token(username: str, roles: list, email: str, is_expired: bool = False) -> str:
    now = int(time.time())
    payload = {
        "sub": f"id-{username}",
        "preferred_username": username,
        "email": email,
        "iat": now,
        "exp": now - 3600 if is_expired else now + 3600,
        "realm_access": {
            "roles": roles
        }
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def simulate_opa_decision(identity: dict, device: dict, request_info: dict) -> dict:
    """
    Python reference model mirror of policies/main.rego for offline integration test execution.
    """
    path = request_info.get("path", "")
    method = request_info.get("method", "GET")
    roles = identity.get("roles", [])
    authenticated = identity.get("authenticated", False)

    violations = []

    # 1. Authentication check
    if not authenticated:
        violations.append("Authentication required: Missing or invalid JWT credentials")
        return {"allowed": False, "violations": violations}

    # 2. RBAC check
    is_finance = path.startswith("/api/finance")
    is_dev = path.startswith("/api/dev")
    rbac_allowed = False

    if is_finance:
        has_finance_role = any(r in {"finance-admin", "finance"} for r in roles)
        has_auditor_role = "auditor" in roles
        if method == "GET" and (has_finance_role or has_auditor_role):
            rbac_allowed = True
        elif method in {"POST", "PUT", "DELETE", "PATCH"} and has_finance_role:
            rbac_allowed = True
        else:
            if method in {"POST", "PUT", "DELETE", "PATCH"} and not has_finance_role:
                violations.append("Access denied: Mutation operations on Finance API require finance-admin")
            else:
                violations.append("Access denied: Missing required role for Finance API")

    elif is_dev:
        if any(r in {"engineering", "developer"} for r in roles):
            rbac_allowed = True
        else:
            violations.append("Access denied: Missing required role for Developer Portal")
    else:
        # Unknown path
        rbac_allowed = False
        violations.append("Access denied: Unknown resource")

    # 3. Posture check
    posture_allowed = True
    valid_os = {"linux", "darwin", "macos", "windows", "windows_10", "windows_11"}

    if not device.get("encrypted", False):
        posture_allowed = False
        violations.append("Device Posture Violation: Disk encryption is disabled")

    if device.get("patch_level") != "current":
        posture_allowed = False
        violations.append("Device Posture Violation: Operating system patch level is outdated")

    if is_finance and not device.get("corporate_managed", False):
        posture_allowed = False
        violations.append("Device Posture Violation: Unmanaged or non-corporate device")

    if device.get("os") not in valid_os:
        posture_allowed = False
        violations.append("Device Posture Violation: Unsupported or untrusted operating system")

    allowed = rbac_allowed and posture_allowed

    return {
        "allowed": allowed,
        "violations": violations,
        "headers": {
            "X-User-Id": identity.get("user", "anonymous"),
            "X-User-Roles": ",".join(roles),
            "X-Auth-Decision": "ALLOWED" if allowed else "DENIED",
            "X-ZTNA-Policy": "NIST-SP-800-207"
        } if allowed else {}
    }


class TestZeroTrustAuthorizationFlows:
    """End-to-end integration scenarios verifying ZTNA security enforcement."""

    @pytest.fixture(autouse=True)
    def setup_mock_opa(self):
        """Patches evaluate_opa_policy to use the reference Rego decision engine."""
        async def _mock_eval(input_payload):
            return simulate_opa_decision(
                input_payload.get("identity", {}),
                input_payload.get("device", {}),
                input_payload.get("request", {})
            )

        with patch("main.evaluate_opa_policy", side_effect=_mock_eval):
            yield

    def test_flow_1_alice_finance_compliant_laptop_allowed(self):
        """Alice (Finance) on compliant corporate device accessing ledger -> Allowed."""
        token = generate_test_token("alice", ["finance-admin"], "alice@corp.local")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=linux,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-User-Id") == "alice"
        assert resp.headers.get("X-Auth-Decision") == "ALLOWED"

    def test_flow_2_alice_unencrypted_laptop_denied(self):
        """Alice (Finance) on unencrypted laptop -> Denied with 403."""
        token = generate_test_token("alice", ["finance-admin"], "alice@corp.local")
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
        assert any("Disk encryption is disabled" in v for v in data["policy_violations"])

    def test_flow_3_alice_outdated_patch_level_denied(self):
        """Alice (Finance) with outdated OS patch level -> Denied with 403."""
        token = generate_test_token("alice", ["finance-admin"], "alice@corp.local")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=linux,patch_level=outdated,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 403
        data = resp.json()
        assert any("patch level is outdated" in v for v in data["policy_violations"])

    def test_flow_4_bob_engineering_dev_portal_allowed(self):
        """Bob (Engineering) on compliant device accessing dev portal -> Allowed."""
        token = generate_test_token("bob", ["engineering"], "bob@corp.local")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=windows_11,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/dev/repositories",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/dev/repositories", headers=headers)
        assert resp.status_code == 200
        assert resp.headers.get("X-User-Id") == "bob"

    def test_flow_5_bob_engineering_accessing_finance_api_denied(self):
        """Bob (Engineering) attempting to access Finance ledger -> Denied with 403 (RBAC)."""
        token = generate_test_token("bob", ["engineering"], "bob@corp.local")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=linux,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 403
        data = resp.json()
        assert any("Missing required role for Finance API" in v for v in data["policy_violations"])

    def test_flow_6_auditor_read_only_allowed(self):
        """Auditor accessing finance ledger GET -> Allowed."""
        token = generate_test_token("charlie", ["auditor"], "charlie@corp.local")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=darwin,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 200

    def test_flow_7_auditor_payout_mutation_denied(self):
        """Auditor attempting POST payout -> Denied with 403."""
        token = generate_test_token("charlie", ["auditor"], "charlie@corp.local")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Device-Posture": "encrypted=true,os=darwin,patch_level=current,corporate_managed=true",
            "X-Envoy-Original-Path": "/api/finance/payout",
            "X-Envoy-Original-Method": "POST"
        }
        resp = client.post("/api/finance/payout", headers=headers)
        assert resp.status_code == 403
        data = resp.json()
        assert any("Mutation operations on Finance API require finance-admin" in v for v in data["policy_violations"])

    def test_flow_8_unauthenticated_request_rejected(self):
        """Request without Authorization header -> 401 Unauthorized."""
        headers = {
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    def test_flow_9_expired_token_rejected(self):
        """Request with expired JWT token -> 401 Unauthorized."""
        token = generate_test_token("alice", ["finance-admin"], "alice@corp.local", is_expired=True)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Envoy-Original-Path": "/api/finance/ledger",
            "X-Envoy-Original-Method": "GET"
        }
        resp = client.get("/api/finance/ledger", headers=headers)
        assert resp.status_code == 401
