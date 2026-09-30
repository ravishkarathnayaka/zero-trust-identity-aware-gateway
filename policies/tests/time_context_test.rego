package ztna.time_context_test

import rego.v1
import data.ztna.time_context

test_business_hours_finance_payout_allowed if {
    input_data := {
        "identity": {"roles": ["finance-admin"]},
        "request": {"path": "/api/finance/payout", "method": "POST"},
        "context": {"time_hour": 14}
    }
    time_context.allow with input as input_data
}

test_off_hours_finance_payout_denied if {
    input_data := {
        "identity": {"roles": ["finance-admin"]},
        "request": {"path": "/api/finance/payout", "method": "POST"},
        "context": {"time_hour": 3}
    }
    not time_context.allow with input as input_data
    some violation in time_context.violations with input as input_data
    contains(violation, "restricted outside business hours")
}

test_off_hours_emergency_override_allowed if {
    input_data := {
        "identity": {"roles": ["finance-admin", "emergency-responder"]},
        "request": {"path": "/api/finance/payout", "method": "POST"},
        "context": {"time_hour": 3}
    }
    time_context.allow with input as input_data
}

test_off_hours_read_allowed if {
    input_data := {
        "identity": {"roles": ["finance-admin"]},
        "request": {"path": "/api/finance/ledger", "method": "GET"},
        "context": {"time_hour": 2}
    }
    time_context.allow with input as input_data
}
