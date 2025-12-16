"""
Falco Event Processor
Processes events from Falco and converts them to ThreatEvent objects
"""
from typing import Optional, Dict, Any
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.storage import threats_db
from app.api.stream import manager


class FalcoProcessor:
    """Processes Falco events and creates ThreatEvent objects"""
    
    # Mapping of Falco priorities to threat severities
    PRIORITY_TO_SEVERITY = {
        "Emergency": ThreatSeverity.CRITICAL,
        "Alert": ThreatSeverity.HIGH,
        "Critical": ThreatSeverity.HIGH,
        "Error": ThreatSeverity.MEDIUM,
        "Warning": ThreatSeverity.MEDIUM,
        "Notice": ThreatSeverity.LOW,
        "Informational": ThreatSeverity.LOW,
        "Debug": ThreatSeverity.LOW
    }
    
    # Keyword-based threat type detection
    THREAT_KEYWORDS = {
        ThreatType.REVERSE_SHELL: ["reverse shell", "nc ", "netcat", "bash -i", "/bin/sh", "shell"],
        ThreatType.PRIVILEGE_ESCALATION: ["sudo", "su ", "setuid", "setgid", "capabilities"],
        ThreatType.UNAUTHORIZED_ACCESS: ["unauthorized", "forbidden", "access denied"],
        ThreatType.MALICIOUS_PROCESS: ["malware", "virus", "trojan", "backdoor"],
        ThreatType.NETWORK_ANOMALY: ["port scan", "brute force", "ddos"],
        ThreatType.FILE_ANOMALY: ["sensitive file", "password", "secret", "credential"],
        ThreatType.CONTAINER_ESCAPE: ["container escape", "host mount", "privileged"]
    }
    
    async def process_event(self, event: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Process a Falco event and create a ThreatEvent
        
        Expected Falco event format:
        {
            "output": "17:20:42.123456789: Warning ...",
            "priority": "Warning",
            "rule": "Terminal shell in container",
            "time": "2024-01-01T17:20:42.123456789Z",
            "output_fields": {
                "k8s.pod.name": "evil-pod",
                "k8s.ns.name": "default",
                "container.name": "evil-container",
                ...
            }
        }
        """
        try:
            # Extract Falco event data
            output = event.get("output", "")
            priority = event.get("priority", "Informational")
            rule = event.get("rule", "Unknown")
            output_fields = event.get("output_fields", {})
            
            # Determine severity
            severity = self.PRIORITY_TO_SEVERITY.get(priority, ThreatSeverity.LOW)
            
            # Detect threat type from keywords
            threat_type = self._detect_threat_type(output.lower(), rule.lower())
            
            # Extract Kubernetes metadata
            pod_name = output_fields.get("k8s.pod.name") or output_fields.get("k8s.pod.name")
            namespace = output_fields.get("k8s.ns.name") or output_fields.get("k8s.namespace.name", "default")
            container = output_fields.get("container.name") or output_fields.get("k8s.container.name")
            user = output_fields.get("user.name") or output_fields.get("proc.user")
            
            # Create threat event
            threat = ThreatEvent(
                severity=severity,
                threat_type=threat_type,
                source_pod=pod_name,
                source_namespace=namespace,
                source_container=container,
                source_user=user,
                description=output[:500],  # Truncate long outputs
                falco_output=output,
                falco_rule=rule,
                falco_priority=priority,
                raw_event=event,
                confidence=0.7  # Default confidence, will be updated by ML/RL
            )
            
            # Store threat
            threats_db.append(threat)
            
            # Broadcast to WebSocket clients
            await manager.broadcast({
                "type": "threat_detected",
                "threat_id": str(threat.id),
                "severity": threat.severity.value,
                "threat_type": threat.threat_type.value,
                "pod": threat.source_pod,
                "description": threat.description[:100]
            })
            
            print(f"🔍 Threat detected: {threat.threat_type.value} in {threat.source_pod} (severity: {threat.severity.value})")
            
            return threat
        
        except Exception as e:
            print(f"❌ Error processing Falco event: {e}")
            return None
    
    def _detect_threat_type(self, output: str, rule: str) -> ThreatType:
        """Detect threat type from output and rule keywords"""
        combined = f"{output} {rule}"
        
        for threat_type, keywords in self.THREAT_KEYWORDS.items():
            if any(keyword in combined for keyword in keywords):
                return threat_type
        
        return ThreatType.UNKNOWN
