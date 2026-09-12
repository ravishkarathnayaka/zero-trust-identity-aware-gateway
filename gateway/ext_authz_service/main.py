"""
ZTNA ExtAuthz Authorization Middleware.
Compliant with NIST SP 800-207 Zero Trust Architecture.
Bridges Envoy Proxy (PEP) to Keycloak (IdP) and Open Policy Agent (PDP).
"""

import os
import json
import logging
import datetime
from typing import Dict, Any, Optional, Tuple

import httpx
import jwt
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse

# Configure Structured Logging
logger = logging.getLogger("ztna_ext_authz")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# Configuration from Environment
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "ztna-realm")
OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
VERIFY_JWT_SIGNATURE = os.getenv("VERIFY_JWT_SIGNATURE", "false").lower() in ("true", "1", "yes")
OPA_TIMEOUT_SECONDS = float(os.getenv("OPA_TIMEOUT_SECONDS", "2.0"))

app = FastAPI(
    title="ZTNA ExtAuthz Middleware",
    description="Envoy HTTP External Authorization Service integrating OPA and Keycloak",
    version="1.0.0"
)

# Cache for Keycloak JWKS public keys
_jwks_cache: Dict[str, Any] = {}
_jwks_last_fetched: Optional[datetime.datetime] = None


def fetch_keycloak_jwks() -> Dict[str, Any]:
    """Fetches and caches the JSON Web Key Set from Keycloak."""
    global _jwks_cache, _jwks_last_fetched
    now = datetime.datetime.now(datetime.timezone.utc)
    if _jwks_cache and _jwks_last_fetched and (now - _jwks_last_fetched).total_seconds() < 300:
        return _jwks_cache

    jwks_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(jwks_url)
            if resp.status_code == 200:
                _jwks_cache = resp.json()
                _jwks_last_fetched = now
                logger.info("Successfully fetched and cached Keycloak JWKS keys")
                return _jwks_cache
    except Exception as e:
        logger.warning(f"Could not reach Keycloak JWKS endpoint ({jwks_url}): {e}")

    return _jwks_cache


def parse_device_posture(header_value: Optional[str]) -> Dict[str, Any]:
    """
    Parses device posture signals from incoming header.
    Supports either comma-separated key=value or JSON formatting.
    Example: encrypted=true,os=linux,patch_level=current,corporate_managed=true
    """
    default_posture = {
        "encrypted": False,
        "os": "unknown",
        "patch_level": "outdated",
        "corporate_managed": False
    }

    if not header_value:
        return default_posture

    cleaned = header_value.strip()

    # Try JSON parsing
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            parsed = json.loads(cleaned)
            return {
                "encrypted": bool(parsed.get("encrypted", False)),
                "os": str(parsed.get("os", "unknown")).lower(),
                "patch_level": str(parsed.get("patch_level", "outdated")).lower(),
                "corporate_managed": bool(parsed.get("corporate_managed", False))
            }
        except Exception:
            pass

    # Key-value pair parsing
    posture = dict(default_posture)
    for pair in cleaned.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            key = k.strip().lower()
            val = v.strip()

            if key in ("encrypted", "corporate_managed"):
                posture[key] = val.lower() in ("true", "1", "yes")
            elif key in ("os", "patch_level"):
                posture[key] = val.lower()

    return posture


def extract_and_validate_jwt(auth_header: Optional[str]) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    """
    Validates the Bearer token.
    Returns (is_authenticated, claims, error_message).
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        return False, {}, "Missing or malformed Authorization header"

    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return False, {}, "Empty Bearer token"

    try:
        # Decode without verification first to read header & payload
        unverified_claims = jwt.decode(token, options={"verify_signature": False})
        
        # Check standard expiration
        exp = unverified_claims.get("exp")
        if exp:
            now_ts = datetime.datetime.now(datetime.timezone.utc).timestamp()
            if now_ts > exp:
                return False, {}, "Token has expired"

        # If strict signature verification is required, verify with JWKS
        if VERIFY_JWT_SIGNATURE:
            jwks = fetch_keycloak_jwks()
            if not jwks or "keys" not in jwks:
                logger.warning("JWKS keys unavailable; rejecting token under strict verification")
                return False, {}, "Cannot verify token signature: JWKS unavailable"

            unverified_headers = jwt.get_unverified_header(token)
            kid = unverified_headers.get("kid")
            jwk = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
            if not jwk:
                return False, {}, "Token signing key not recognized by IdP"

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_aud": False}
            )
            return True, claims, None
        else:
            return True, unverified_claims, None

    except jwt.ExpiredSignatureError:
        return False, {}, "Token signature expired"
    except Exception as e:
        logger.error(f"JWT validation failure: {e}")
        return False, {}, f"Invalid token: {str(e)}"


def extract_identity(claims: Dict[str, Any], is_authenticated: bool) -> Dict[str, Any]:
    """Extracts normalized user identity and roles from token claims."""
    if not is_authenticated:
        return {
            "user": "anonymous",
            "email": "",
            "roles": [],
            "authenticated": False
        }

    user = claims.get("preferred_username") or claims.get("sub") or "authenticated_user"
    email = claims.get("email") or ""

    # Extract roles from Keycloak realm_access and resource_access
    roles = []
    realm_access = claims.get("realm_access", {})
    if isinstance(realm_access, dict):
        roles.extend(realm_access.get("roles", []))

    resource_access = claims.get("resource_access", {})
    if isinstance(resource_access, dict):
        for client_roles in resource_access.values():
            if isinstance(client_roles, dict):
                roles.extend(client_roles.get("roles", []))

    # Also handle standard groups or roles claim
    direct_roles = claims.get("roles")
    if isinstance(direct_roles, list):
        roles.extend(direct_roles)

    # De-duplicate roles
    unique_roles = sorted(list(set(roles)))

    return {
        "user": user,
        "email": email,
        "roles": unique_roles,
        "authenticated": True
    }


async def evaluate_opa_policy(input_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Queries the Open Policy Agent (PDP) decision API."""
    endpoint = f"{OPA_URL}/v1/data/ztna/main/decision"
    try:
        async with httpx.AsyncClient(timeout=OPA_TIMEOUT_SECONDS) as client:
            resp = await client.post(endpoint, json={"input": input_payload})
            if resp.status_code == 200:
                body = resp.json()
                return body.get("result", {})
            else:
                logger.error(f"OPA returned non-200 status {resp.status_code}: {resp.text}")
                return {
                    "allowed": False,
                    "violations": [f"PDP Error: OPA returned HTTP {resp.status_code}"]
                }
    except Exception as e:
        logger.critical(f"Failed to communicate with OPA Policy Decision Point: {e}")
        # Zero Trust Fail-Closed Principle
        return {
            "allowed": False,
            "violations": ["Policy Decision Point (OPA) is unavailable - failing closed"]
        }


def emit_security_audit_log(
    user: str,
    roles: list,
    resource: str,
    method: str,
    posture: dict,
    allowed: bool,
    violations: list,
    client_ip: str
):
    """Logs structured JSON audit event for NIST SP 800-207 compliance."""
    audit_event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "ZTNA_AUTHORIZATION_DECISION",
        "nist_component": "Policy Enforcement Point / Policy Administrator",
        "decision": "ALLOW" if allowed else "DENY",
        "subject": {
            "user": user,
            "roles": roles,
            "client_ip": client_ip
        },
        "device_posture": posture,
        "action": method,
        "resource": resource,
        "policy_violations": violations
    }
    logger.info(f"AUDIT: {json.dumps(audit_event)}")


@app.get("/healthz", tags=["System"])
def healthz():
    return {
        "status": "healthy",
        "service": "ext_authz_middleware",
        "keycloak_url": KEYCLOAK_URL,
        "opa_url": OPA_URL,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def authorize_request(full_path: str, request: Request):
    """
    Main authorization entrypoint invoked by Envoy HTTP ext_authz filter.
    Intercepts client request context, queries OPA PDP, and responds to Envoy.
    """
    # Determine the client's actual target path and HTTP method
    headers = request.headers
    target_path = headers.get("x-envoy-original-path") or headers.get("x-original-uri") or f"/{full_path}"
    target_method = headers.get("x-envoy-original-method") or request.method
    client_ip = headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")

    # Bypass internal health checks
    if target_path in ("/healthz", "/extauthz/healthz"):
        return Response(status_code=status.HTTP_200_OK)

    # Device Posture
    posture_header = headers.get("x-device-posture")
    device_posture = parse_device_posture(posture_header)

    # JWT Authentication
    auth_header = headers.get("authorization")
    is_auth, claims, auth_error = extract_and_validate_jwt(auth_header)
    identity = extract_identity(claims, is_auth)

    # Fast-path for unauthenticated non-public requests
    is_public = target_path.startswith("/healthz") or target_path.startswith("/api/public")
    if not is_auth and not is_public:
        emit_security_audit_log(
            user="anonymous",
            roles=[],
            resource=target_path,
            method=target_method,
            posture=device_posture,
            allowed=False,
            violations=[auth_error or "Authentication required"],
            client_ip=client_ip
        )
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "status": "UNAUTHORIZED",
                "error": "AuthenticationRequired",
                "detail": auth_error or "Valid Bearer JWT required",
                "target_resource": target_path
            },
            headers={"WWW-Authenticate": 'Bearer realm="ztna-gateway"'}
        )

    # Build OPA Context
    opa_input = {
        "identity": identity,
        "device": device_posture,
        "request": {
            "path": target_path,
            "method": target_method
        },
        "context": {
            "client_ip": client_ip,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
    }

    # Query OPA PDP
    pdp_decision = await evaluate_opa_policy(opa_input)
    allowed = pdp_decision.get("allowed", False)
    violations = pdp_decision.get("violations", [])

    # Audit log decision
    emit_security_audit_log(
        user=identity["user"],
        roles=identity["roles"],
        resource=target_path,
        method=target_method,
        posture=device_posture,
        allowed=allowed,
        violations=violations,
        client_ip=client_ip
    )

    if allowed:
        # HTTP 200 OK instructs Envoy to allow the request
        # Envoy will inject these response headers into the upstream request
        downstream_headers = pdp_decision.get("headers", {})
        response_headers = {
            "X-User-Id": downstream_headers.get("X-User-Id", identity["user"]),
            "X-User-Roles": downstream_headers.get("X-User-Roles", ",".join(identity["roles"])),
            "X-Auth-Decision": "ALLOWED",
            "X-ZTNA-Policy": "NIST-SP-800-207"
        }
        return Response(status_code=status.HTTP_200_OK, headers=response_headers)
    else:
        # HTTP 403 Forbidden instructs Envoy to block the request
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status": "DENIED",
                "error": "AccessDeniedByPolicy",
                "framework": "NIST-SP-800-207",
                "user": identity["user"],
                "target_resource": target_path,
                "method": target_method,
                "policy_violations": violations,
                "device_posture_evaluated": device_posture,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9001)
