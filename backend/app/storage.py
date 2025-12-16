"""
Shared Storage Module
In-memory storage for prototype (will be replaced with database in Phase 2)
"""
from typing import List
from app.models.threat_event import ThreatEvent
from app.models.remediation_action import RemediationAction

# Shared in-memory storage
threats_db: List[ThreatEvent] = []
actions_db: List[RemediationAction] = []
