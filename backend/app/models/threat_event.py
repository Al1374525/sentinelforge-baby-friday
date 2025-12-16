"""
Threat Event Model
Represents a detected security threat
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import uuid4, UUID
from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    """Types of threats"""
    REVERSE_SHELL = "reverse_shell"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALICIOUS_PROCESS = "malicious_process"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_ANOMALY = "file_anomaly"
    CONTAINER_ESCAPE = "container_escape"
    UNKNOWN = "unknown"


class ThreatEvent(BaseModel):
    """Represents a security threat event"""
    id: UUID = Field(default_factory=uuid4)
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    threat_type: ThreatType = ThreatType.UNKNOWN
    
    # Source information
    source_pod: Optional[str] = None
    source_namespace: Optional[str] = None
    source_container: Optional[str] = None
    source_user: Optional[str] = None
    
    # Threat details
    description: str = ""
    falco_output: str = ""
    falco_rule: Optional[str] = None
    falco_priority: Optional[str] = None
    
    # Detection scores
    ml_score: Optional[float] = None  # Anomaly detection score (0-1)
    confidence: float = 0.0  # Overall confidence (0-1)
    
    # Raw event data
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    
    # Status
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }
