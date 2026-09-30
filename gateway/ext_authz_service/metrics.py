"""
Prometheus Metrics Module for ZTNA ExtAuthz Service.
Collects continuous authorization metrics aligned with NIST SP 800-207.
"""

import time
from typing import Dict

# In-memory Prometheus metric counters
_metrics = {
    "ztna_evaluations_total": {"allow": 0, "deny": 0},
    "ztna_violations_total": {},
    "ztna_active_requests": 0,
    "ztna_evaluation_duration_seconds_sum": 0.0,
    "ztna_evaluation_duration_seconds_count": 0
}

def record_evaluation(allowed: bool, duration_seconds: float):
    decision = "allow" if allowed else "deny"
    _metrics["ztna_evaluations_total"][decision] += 1
    _metrics["ztna_evaluation_duration_seconds_sum"] += duration_seconds
    _metrics["ztna_evaluation_duration_seconds_count"] += 1

def record_violation(violation_name: str):
    clean_name = violation_name.replace('"', "").strip()
    _metrics["ztna_violations_total"][clean_name] = (
        _metrics["ztna_violations_total"].get(clean_name, 0) + 1
    )

def generate_prometheus_metrics() -> str:
    lines = [
        "# HELP ztna_evaluations_total Total number of authorization decisions by ExtAuthz PEP",
        "# TYPE ztna_evaluations_total counter",
        f'ztna_evaluations_total{{decision="allow"}} {_metrics["ztna_evaluations_total"]["allow"]}',
        f'ztna_evaluations_total{{decision="deny"}} {_metrics["ztna_evaluations_total"]["deny"]}',
        "",
        "# HELP ztna_evaluation_duration_seconds Latency of Policy Decision Point evaluations",
        "# TYPE ztna_evaluation_duration_seconds summary",
        f'ztna_evaluation_duration_seconds_sum {_metrics["ztna_evaluation_duration_seconds_sum"]:.6f}',
        f'ztna_evaluation_duration_seconds_count {_metrics["ztna_evaluation_duration_seconds_count"]}',
        ""
    ]

    if _metrics["ztna_violations_total"]:
        lines.append("# HELP ztna_violations_total Count of specific policy violations")
        lines.append("# TYPE ztna_violations_total counter")
        for reason, count in _metrics["ztna_violations_total"].items():
            safe_reason = reason.replace('"', '\\"').replace("\n", " ")
            lines.append(f'ztna_violations_total{{reason="{safe_reason}"}} {count}')
        lines.append("")

    return "\n".join(lines) + "\n"
