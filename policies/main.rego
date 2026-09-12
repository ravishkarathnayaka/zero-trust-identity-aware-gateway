package ztna.main

import rego.v1
import data.ztna.posture
import data.ztna.rbac

# Default deny
default allow := false

# Identity extraction with safe defaults
user_id := object.get(input, ["identity", "user"], "anonymous")
user_roles := object.get(input, ["identity", "roles"], [])
is_authenticated := object.get(input, ["identity", "authenticated"], false)

# Master authorization logic
# Public endpoints bypass identity and posture evaluation
allow if rbac.is_public

# Protected endpoints require valid identity, RBAC authorization, and compliant posture
allow if {
    is_authenticated
    rbac.allow
    posture.allow
}

# Collect all policy violations
violations contains "Authentication required: Missing or invalid JWT credentials" if {
    not rbac.is_public
    not is_authenticated
}

violations contains msg if {
    not rbac.is_public
    is_authenticated
    some msg in rbac.violations
}

violations contains msg if {
    not rbac.is_public
    some msg in posture.violations
}

# Downstream identity headers injected upon successful authorization
downstream_headers := {
    "X-User-Id": user_id,
    "X-User-Roles": concat(",", user_roles),
    "X-Auth-Decision": "ALLOWED",
    "X-ZTNA-Policy": "NIST-SP-800-207"
} if {
    allow
} else := {}

# Comprehensive decision summary for ExtAuthz middleware and audit logging
decision := {
    "allowed": allow,
    "user": user_id,
    "roles": user_roles,
    "resource": object.get(input, ["request", "path"], ""),
    "method": object.get(input, ["request", "method"], ""),
    "violations": violations,
    "headers": downstream_headers
}
