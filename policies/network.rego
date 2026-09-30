package ztna.network

import rego.v1

# Default network decision
default allow := true

# Trusted enterprise CIDRs
trusted_corporate_cidrs := [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "172.24.0.0/16",
    "192.168.0.0/16",
    "127.0.0.1/32"
]

# Explicitly blocked / high-risk CIDRs
blocked_external_cidrs := [
    "198.51.100.0/24",
    "203.0.113.0/24"
]

client_ip := object.get(input, ["context", "client_ip"], "127.0.0.1")

is_trusted_cidr if {
    some cidr in trusted_corporate_cidrs
    net.cidr_contains(cidr, client_ip)
}

is_blocked_cidr if {
    some cidr in blocked_external_cidrs
    net.cidr_contains(cidr, client_ip)
}

# Network access rule:
# Block if IP is in the explicitly blocked CIDRs
allow := false if {
    is_blocked_cidr
}

# Informative network violations
violations contains "Network Policy Violation: Request originated from blocked or high-risk IP range" if {
    is_blocked_cidr
}
