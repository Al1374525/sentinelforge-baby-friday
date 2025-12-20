"""
SQLAlchemy database models
"""
from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, JSON, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid
from app.models.threat_event import ThreatSeverity, ThreatType
from app.models.remediation_action import ActionType, RiskLevel

Base = declarative_base()


class ThreatEventDB(Base):
    """Threat event database model"""
    __tablename__ = "threat_events"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    severity = Column(SQLEnum(ThreatSeverity), nullable=False)
    threat_type = Column(SQLEnum(ThreatType), nullable=False)
    
    # Source information
    source_pod = Column(String(255), nullable=True)
    source_namespace = Column(String(255), nullable=True)
    source_container = Column(String(255), nullable=True)
    source_user = Column(String(255), nullable=True)
    
    # Threat details
    description = Column(Text, nullable=False, default="")
    falco_output = Column(Text, nullable=False, default="")
    falco_rule = Column(String(255), nullable=True)
    falco_priority = Column(String(50), nullable=True)
    
    # Detection scores
    ml_score = Column(Float, nullable=True)
    confidence = Column(Float, default=0.0, nullable=False)
    
    # Raw event data
    raw_event = Column(JSON, nullable=True)
    
    # Status
    resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    
    def to_pydantic(self):
        """Convert to Pydantic model"""
        from app.models.threat_event import ThreatEvent
        return ThreatEvent(
            id=self.id,
            detected_at=self.detected_at,
            severity=self.severity,
            threat_type=self.threat_type,
            source_pod=self.source_pod,
            source_namespace=self.source_namespace,
            source_container=self.source_container,
            source_user=self.source_user,
            description=self.description,
            falco_output=self.falco_output,
            falco_rule=self.falco_rule,
            falco_priority=self.falco_priority,
            ml_score=self.ml_score,
            confidence=self.confidence,
            raw_event=self.raw_event or {},
            resolved=self.resolved,
            resolved_at=self.resolved_at
        )


class RemediationActionDB(Base):
    """Remediation action database model"""
    __tablename__ = "remediation_actions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    action_type = Column(SQLEnum(ActionType), nullable=False)
    risk_level = Column(SQLEnum(RiskLevel), nullable=False)
    
    # Decision metrics
    confidence = Column(Float, default=0.0, nullable=False)
    ml_score = Column(Float, nullable=True)
    
    # Execution details
    executed = Column(Boolean, default=False, nullable=False)
    executed_at = Column(DateTime, nullable=True)
    success = Column(Boolean, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Action parameters
    parameters = Column(JSON, nullable=True)
    
    # Human confirmation
    requires_confirmation = Column(Boolean, default=False, nullable=False)
    confirmed_by = Column(String(255), nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
    
    def to_pydantic(self):
        """Convert to Pydantic model"""
        from app.models.remediation_action import RemediationAction
        return RemediationAction(
            id=self.id,
            threat_id=self.threat_id,
            action_type=self.action_type,
            risk_level=self.risk_level,
            confidence=self.confidence,
            ml_score=self.ml_score,
            executed=self.executed,
            executed_at=self.executed_at,
            success=self.success,
            error_message=self.error_message,
            parameters=self.parameters or {},
            requires_confirmation=self.requires_confirmation,
            confirmed_by=self.confirmed_by,
            confirmed_at=self.confirmed_at
        )
