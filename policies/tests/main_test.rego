package ztna.main_test

import rego.v1
import data.ztna.main

# Sample Contexts
alice_identity := {
    "user": "alice",
    "email": "alice@corp.local",
    "roles": ["finance-admin"],
    "authenticated": true
}

bob_identity := {
    "user": "bob",
    "email": "bob@corp.local",
    "roles": ["engineering"],
    "authenticated": true
}

auditor_identity := {
    "user": "charlie",
    "email": "charlie@corp.local",
    "roles": ["auditor"],
    "authenticated": true
}

eve_identity := {
    "user": "eve",
    "email": "eve@corp.local",
    "roles": [],
    "authenticated": true
}

unauthenticated_identity := {
    "user": "anonymous",
    "roles": [],
    "authenticated": false
}

compliant_device := {
    "encrypted": true,
    "os": "linux",
    "patch_level": "current",
    "corporate_managed": true
}

unencrypted_device := {
    "encrypted": false,
    "os": "linux",
    "patch_level": "current",
    "corporate_managed": true
}

outdated_device := {
    "encrypted": true,
    "os": "linux",
    "patch_level": "outdated",
    "corporate_managed": true
}

unmanaged_device := {
    "encrypted": true,
    "os": "windows_11",
    "patch_level": "current",
    "corporate_managed": false
}

unsupported_os_device := {
    "encrypted": true,
    "os": "unknown_os",
    "patch_level": "current",
    "corporate_managed": true
}

# 1. Public Health Endpoint Allowed Without Authentication
test_public_healthz_allowed if {
    input_data := {
        "identity": unauthenticated_identity,
        "device": unmanaged_device,
        "request": {
            "path": "/healthz",
            "method": "GET"
        }
    }
    main.allow with input as input_data
}

# 2. Alice (Finance-Admin) with Compliant Corporate Laptop Accessing Finance Ledger
test_alice_finance_ledger_allowed if {
    input_data := {
        "identity": alice_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == true
    dec.headers["X-User-Id"] == "alice"
    dec.headers["X-User-Roles"] == "finance-admin"
}

# 3. Alice with Unencrypted Disk Denied Access to Finance API (Device Posture Failure)
test_alice_finance_unencrypted_denied if {
    input_data := {
        "identity": alice_identity,
        "device": unencrypted_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    not main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == false
    some violation in dec.violations
    contains(violation, "Disk encryption is disabled")
}

# 4. Alice with Outdated Patch Level Denied Access to Finance API
test_alice_finance_outdated_patch_denied if {
    input_data := {
        "identity": alice_identity,
        "device": outdated_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    not main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == false
    some violation in dec.violations
    contains(violation, "patch level is outdated")
}

# 5. Alice with Unmanaged Device Denied High-Sensitivity Finance API
test_alice_finance_unmanaged_device_denied if {
    input_data := {
        "identity": alice_identity,
        "device": unmanaged_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    not main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == false
    some violation in dec.violations
    contains(violation, "Unmanaged or non-corporate device")
}

# 6. Bob (Engineering) with Compliant Laptop Accessing Dev Portal
test_bob_dev_portal_allowed if {
    input_data := {
        "identity": bob_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/dev/repositories",
            "method": "GET"
        }
    }
    main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == true
    dec.headers["X-User-Id"] == "bob"
}

# 7. Bob (Engineering) Denied Access to Finance API (RBAC Failure)
test_bob_finance_denied if {
    input_data := {
        "identity": bob_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    not main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == false
    some violation in dec.violations
    contains(violation, "Missing required role for Finance API")
}

# 8. Unauthenticated User Accessing Protected Path Denied
test_unauthenticated_request_denied if {
    input_data := {
        "identity": unauthenticated_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/dev/repositories",
            "method": "GET"
        }
    }
    not main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == false
    some violation in dec.violations
    contains(violation, "Authentication required")
}

# 9. Eve (No Roles) Accessing Protected Services Denied
test_eve_no_roles_denied if {
    input_data := {
        "identity": eve_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    not main.allow with input as input_data
}

# 10. Auditor Read-Only Allowed on Finance API, but Mutation Denied
test_auditor_finance_read_allowed if {
    input_data := {
        "identity": auditor_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/finance/ledger",
            "method": "GET"
        }
    }
    main.allow with input as input_data
}

test_auditor_finance_mutation_denied if {
    input_data := {
        "identity": auditor_identity,
        "device": compliant_device,
        "request": {
            "path": "/api/finance/payout",
            "method": "POST"
        }
    }
    not main.allow with input as input_data
    dec := main.decision with input as input_data
    dec.allowed == false
}
