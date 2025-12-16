"""
Remediation Action Model
Represents an action taken to remediate a threat
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
from uuid import uuid4, UUID
from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Types of remediation actions"""
    MONITOR = "monitor"  # No action, just monitor
    LOG = "log"  # Log the event
    ALERT = "alert"  # Send alert
    ISOLATE_POD = "isolate_pod"  # Apply network policy to isolate pod
    TERMINATE_POD = "terminate_pod"  # Terminate the pod
    BLOCK_NETWORK = "block_network"  # Block network connection
    TERMINATE_PROCESS = "terminate_process"  # Terminate specific process
    ESCALATE = "escalate"  # Escalate to human operator


class RiskLevel(str, Enum):
    """Risk level of the action"""
    LOW = "low"  # Safe to auto-execute
    MEDIUM = "medium"  # May require confirmation
    HIGH = "high"  # Requires human confirmation


class RemediationAction(BaseModel):
    """Represents a remediation action"""
    id: UUID = Field(default_factory=uuid4)
    threat_id: UUID
    action_type: ActionType = ActionType.MONITOR
    risk_level: RiskLevel = RiskLevel.LOW
    
    # Decision metrics
    confidence: float = 0.0  # RL agent confidence (0-1)
    ml_score: Optional[float] = None  # ML anomaly score
    
    # Execution details
    executed: bool = False
    executed_at: Optional[datetime] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
    
    # Action parameters
    parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Human confirmation
    requires_confirmation: bool = False
    confirmed_by: Optional[str] = None
    confirmed_at: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }
