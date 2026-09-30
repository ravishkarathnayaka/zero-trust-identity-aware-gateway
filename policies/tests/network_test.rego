package ztna.network_test

import rego.v1
import data.ztna.network

test_trusted_corporate_ip_allowed if {
    input_data := {
        "context": {
            "client_ip": "10.100.5.24"
        }
    }
    network.allow with input as input_data
}

test_localhost_allowed if {
    input_data := {
        "context": {
            "client_ip": "127.0.0.1"
        }
    }
    network.allow with input as input_data
}

test_blocked_external_ip_denied if {
    input_data := {
        "context": {
            "client_ip": "198.51.100.45"
        }
    }
    not network.allow with input as input_data
    some violation in network.violations with input as input_data
    contains(violation, "blocked or high-risk IP range")
}
