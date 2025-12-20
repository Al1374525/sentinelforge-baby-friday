"""
Shared Storage Module
Database-backed storage with fallback to in-memory for compatibility
"""
from typing import List, Optional
from app.models.threat_event import ThreatEvent
from app.models.remediation_action import RemediationAction
from app.database.connection import get_db, init_db, SessionLocal
from app.database.models import ThreatEventDB, RemediationActionDB
import os

# Use database if DATABASE_URL is set, otherwise use in-memory
USE_DATABASE = os.getenv("DATABASE_URL") is not None

# Initialize database if using it
if USE_DATABASE:
    try:
        init_db()
    except Exception as e:
        print(f"⚠️  Database initialization failed: {e}, falling back to in-memory storage")
        USE_DATABASE = False

# Fallback in-memory storage for compatibility
_threats_db: List[ThreatEvent] = []
_actions_db: List[RemediationAction] = []


def get_threats_db() -> List[ThreatEvent]:
    """Get threats from database or in-memory storage"""
    if USE_DATABASE:
        try:
            db = SessionLocal()
            try:
                threats = db.query(ThreatEventDB).all()
                return [threat.to_pydantic() for threat in threats]
            finally:
                db.close()
        except Exception as e:
            print(f"⚠️  Database query failed: {e}, using in-memory storage")
            return _threats_db
    return _threats_db


def get_actions_db() -> List[RemediationAction]:
    """Get actions from database or in-memory storage"""
    if USE_DATABASE:
        try:
            db = SessionLocal()
            try:
                actions = db.query(RemediationActionDB).all()
                return [action.to_pydantic() for action in actions]
            finally:
                db.close()
        except Exception as e:
            print(f"⚠️  Database query failed: {e}, using in-memory storage")
            return _actions_db
    return _actions_db


def add_threat(threat: ThreatEvent) -> None:
    """Add threat to database or in-memory storage"""
    if USE_DATABASE:
        try:
            db = SessionLocal()
            try:
                threat_db = ThreatEventDB(
                    id=threat.id,
                    detected_at=threat.detected_at,
                    severity=threat.severity,
                    threat_type=threat.threat_type,
                    source_pod=threat.source_pod,
                    source_namespace=threat.source_namespace,
                    source_container=threat.source_container,
                    source_user=threat.source_user,
                    description=threat.description,
                    falco_output=threat.falco_output,
                    falco_rule=threat.falco_rule,
                    falco_priority=threat.falco_priority,
                    ml_score=threat.ml_score,
                    confidence=threat.confidence,
                    raw_event=threat.raw_event,
                    resolved=threat.resolved,
                    resolved_at=threat.resolved_at
                )
                db.add(threat_db)
                db.commit()
            finally:
                db.close()
            return
        except Exception as e:
            print(f"⚠️  Database insert failed: {e}, using in-memory storage")
    _threats_db.append(threat)


def add_action(action: RemediationAction) -> None:
    """Add action to database or in-memory storage"""
    if USE_DATABASE:
        try:
            db = SessionLocal()
            try:
                action_db = RemediationActionDB(
                    id=action.id,
                    threat_id=action.threat_id,
                    action_type=action.action_type,
                    risk_level=action.risk_level,
                    confidence=action.confidence,
                    ml_score=action.ml_score,
                    executed=action.executed,
                    executed_at=action.executed_at,
                    success=action.success,
                    error_message=action.error_message,
                    parameters=action.parameters,
                    requires_confirmation=action.requires_confirmation,
                    confirmed_by=action.confirmed_by,
                    confirmed_at=action.confirmed_at
                )
                db.add(action_db)
                db.commit()
            finally:
                db.close()
            return
        except Exception as e:
            print(f"⚠️  Database insert failed: {e}, using in-memory storage")
    _actions_db.append(action)


# For backward compatibility, expose as properties
@property
def threats_db() -> List[ThreatEvent]:
    """Backward compatibility property for threats_db"""
    return get_threats_db()


@property
def actions_db() -> List[RemediationAction]:
    """Backward compatibility property for actions_db"""
    return get_actions_db()


# Create module-level accessors that work with both database and in-memory
class Storage:
    """Storage accessor that works with both database and in-memory"""
    
    @property
    def threats_db(self) -> List[ThreatEvent]:
        return get_threats_db()
    
    @property
    def actions_db(self) -> List[RemediationAction]:
        return get_actions_db()
    
    def append_threat(self, threat: ThreatEvent) -> None:
        add_threat(threat)
    
    def append_action(self, action: RemediationAction) -> None:
        add_action(action)


# For backward compatibility, create list-like objects
class ThreatsList:
    """List-like interface for threats"""
    
    def __iter__(self):
        return iter(get_threats_db())
    
    def __len__(self):
        return len(get_threats_db())
    
    def __getitem__(self, index):
        return get_threats_db()[index]
    
    def append(self, threat: ThreatEvent) -> None:
        add_threat(threat)
    
    def extend(self, threats: list) -> None:
        for threat in threats:
            add_threat(threat)
    
    def clear(self) -> None:
        if USE_DATABASE:
            try:
                db = SessionLocal()
                try:
                    db.query(ThreatEventDB).delete()
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass
        _threats_db.clear()


class ActionsList:
    """List-like interface for actions"""
    
    def __iter__(self):
        return iter(get_actions_db())
    
    def __len__(self):
        return len(get_actions_db())
    
    def __getitem__(self, index):
        return get_actions_db()[index]
    
    def append(self, action: RemediationAction) -> None:
        add_action(action)
    
    def extend(self, actions: list) -> None:
        for action in actions:
            add_action(action)
    
    def clear(self) -> None:
        if USE_DATABASE:
            try:
                db = SessionLocal()
                try:
                    db.query(RemediationActionDB).delete()
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass
        _actions_db.clear()


# Export list-like objects for backward compatibility
threats_db = ThreatsList()
actions_db = ActionsList()
