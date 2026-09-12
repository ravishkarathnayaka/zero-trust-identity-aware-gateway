package ztna.rbac

import rego.v1

# Default deny
default allow := false

# Public endpoints that bypass RBAC
public_endpoints := [
    "/healthz",
    "/api/public/"
]

is_public if {
    some endpoint in public_endpoints
    startswith(input.request.path, endpoint)
}

# Role mapping by resource prefix
is_finance_path if startswith(input.request.path, "/api/finance")
is_dev_path if startswith(input.request.path, "/api/dev")

# Check if user holds finance-admin role
has_finance_role if {
    some role in input.identity.roles
    role in {"finance-admin", "finance"}
}

# Check if user holds engineering role
has_engineering_role if {
    some role in input.identity.roles
    role in {"engineering", "developer"}
}

# Check if user holds auditor role (read-only)
has_auditor_role if {
    some role in input.identity.roles
    role == "auditor"
}

is_auditor_read if {
    input.request.method == "GET"
    has_auditor_role
}

# Allow logic for public endpoints
allow if is_public

# Allow logic for Finance endpoints
allow if {
    is_finance_path
    input.request.method == "GET"
    has_finance_role
}

allow if {
    is_finance_path
    is_auditor_read
}

allow if {
    is_finance_path
    input.request.method in {"POST", "PUT", "DELETE", "PATCH"}
    has_finance_role
}

# Allow logic for Dev Portal endpoints
allow if {
    is_dev_path
    has_engineering_role
}

# Informative RBAC violation reasons
violations contains "Access denied: Missing required role for Finance API" if {
    is_finance_path
    not has_finance_role
    not is_auditor_read
}

violations contains "Access denied: Missing required role for Developer Portal" if {
    is_dev_path
    not has_engineering_role
}

violations contains "Access denied: Mutation operations on Finance API require finance-admin" if {
    is_finance_path
    input.request.method in {"POST", "PUT", "DELETE", "PATCH"}
    not has_finance_role
}
