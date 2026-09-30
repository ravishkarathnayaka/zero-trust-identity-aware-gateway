package ztna.time_context

import rego.v1

# Default time context allows standard requests
default allow := true

# Business hours definition (06:00 to 22:00 UTC)
start_hour := 6
end_hour := 22

current_hour := object.get(input, ["context", "time_hour"], 12)
is_mutation := input.request.method in {"POST", "PUT", "DELETE", "PATCH"}
is_finance := startswith(input.request.path, "/api/finance")

# Check if current hour falls within corporate working hours
is_business_hours if {
    current_hour >= start_hour
    current_hour <= end_hour
}

# Check if user has emergency out-of-hours override role
has_emergency_override if {
    some role in input.identity.roles
    role == "emergency-responder"
}

# Disallow sensitive finance mutations outside business hours without emergency override
allow := false if {
    is_finance
    is_mutation
    not is_business_hours
    not has_emergency_override
}

violations contains "Time Context Violation: Financial mutations are restricted outside business hours (06:00 - 22:00 UTC)" if {
    is_finance
    is_mutation
    not is_business_hours
    not has_emergency_override
}
