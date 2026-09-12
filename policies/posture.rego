package ztna.posture

import rego.v1

# Default posture decision
default allow := false

# Approved corporate operating systems
valid_operating_systems := {
    "linux",
    "darwin",
    "macos",
    "windows",
    "windows_10",
    "windows_11"
}

# Base device posture checks
is_encrypted if {
    input.device.encrypted == true
}

is_patched if {
    input.device.patch_level == "current"
}

is_corporate_managed if {
    input.device.corporate_managed == true
}

is_valid_os if {
    input.device.os in valid_operating_systems
}

# Determine target security sensitivity tier
is_high_sensitivity if {
    startswith(input.request.path, "/api/finance")
}

is_medium_sensitivity if {
    startswith(input.request.path, "/api/dev")
}

# High-sensitivity endpoints require full posture compliance:
# Disk encryption, corporate management, current patches, and trusted OS
allow if {
    is_high_sensitivity
    is_encrypted
    is_patched
    is_corporate_managed
    is_valid_os
}

# Medium-sensitivity endpoints require disk encryption, trusted OS, and patch compliance
allow if {
    is_medium_sensitivity
    is_encrypted
    is_valid_os
    is_patched
}

# Default allow for public routes that do not require device posture
allow if {
    not is_high_sensitivity
    not is_medium_sensitivity
}

# Collect specific posture violations for troubleshooting and audit logs
violations contains "Device Posture Violation: Disk encryption is disabled" if {
    not is_encrypted
}

violations contains "Device Posture Violation: Operating system patch level is outdated" if {
    not is_patched
}

violations contains "Device Posture Violation: Unmanaged or non-corporate device" if {
    is_high_sensitivity
    not is_corporate_managed
}

violations contains "Device Posture Violation: Unsupported or untrusted operating system" if {
    not is_valid_os
}
