"""
Unit tests for actions API endpoints
"""
import pytest
from fastapi.testclient import TestClient
from app.models.remediation_action import ActionType, RiskLevel
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType


@pytest.mark.unit
class TestActionsAPI:
    """Test actions API endpoints"""
    
    def test_list_actions_empty(self, test_client, reset_storage):
        """Test listing actions when none exist"""
        response = test_client.get("/api/v1/actions")
        
        assert response.status_code == 200
        assert response.json() == []
    
    def test_list_actions(self, test_client, reset_storage):
        """Test listing actions"""
        from app.storage import actions_db, threats_db
        from app.models.remediation_action import RemediationAction
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            description="Test threat"
        )
        threats_db.append(threat)
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.HIGH,
            confidence=0.9
        )
        actions_db.append(action)
        
        response = test_client.get("/api/v1/actions")
        
        assert response.status_code == 200
        actions = response.json()
        assert len(actions) == 1
        assert actions[0]["id"] == str(action.id)
        assert actions[0]["action_type"] == "terminate_pod"
    
    def test_list_actions_filter_by_type(self, test_client, reset_storage):
        """Test filtering actions by type"""
        from app.storage import actions_db, threats_db
        from app.models.remediation_action import RemediationAction
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN,
            description="Test"
        )
        threats_db.append(threat)
        
        action1 = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.HIGH
        )
        action2 = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ALERT,
            risk_level=RiskLevel.LOW
        )
        actions_db.extend([action1, action2])
        
        response = test_client.get("/api/v1/actions?action_type=terminate_pod")
        
        assert response.status_code == 200
        actions = response.json()
        assert len(actions) == 1
        assert actions[0]["action_type"] == "terminate_pod"
    
    def test_list_actions_filter_by_executed(self, test_client, reset_storage):
        """Test filtering actions by executed status"""
        from app.storage import actions_db, threats_db
        from app.models.remediation_action import RemediationAction
        from datetime import datetime
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN,
            description="Test"
        )
        threats_db.append(threat)
        
        action_executed = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ALERT,
            risk_level=RiskLevel.LOW,
            executed=True,
            executed_at=datetime.utcnow(),
            success=True
        )
        action_pending = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.MONITOR,
            risk_level=RiskLevel.LOW,
            executed=False
        )
        actions_db.extend([action_executed, action_pending])
        
        # Filter executed
        response = test_client.get("/api/v1/actions?executed=true")
        assert response.status_code == 200
        actions = response.json()
        assert len(actions) == 1
        assert actions[0]["executed"] is True
        
        # Filter pending
        response = test_client.get("/api/v1/actions?executed=false")
        assert response.status_code == 200
        actions = response.json()
        assert len(actions) == 1
        assert actions[0]["executed"] is False
    
    def test_list_actions_limit(self, test_client, reset_storage):
        """Test limiting number of actions returned"""
        from app.storage import actions_db, threats_db
        from app.models.remediation_action import RemediationAction
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN,
            description="Test"
        )
        threats_db.append(threat)
        
        # Create 5 actions
        for i in range(5):
            action = RemediationAction(
                threat_id=threat.id,
                action_type=ActionType.MONITOR,
                risk_level=RiskLevel.LOW
            )
            actions_db.append(action)
        
        # Limit to 2
        response = test_client.get("/api/v1/actions?limit=2")
        
        assert response.status_code == 200
        actions = response.json()
        assert len(actions) == 2
    
    def test_get_action_by_id(self, test_client, reset_storage):
        """Test getting action by ID"""
        from app.storage import actions_db, threats_db
        from app.models.remediation_action import RemediationAction
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            description="Test threat"
        )
        threats_db.append(threat)
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.HIGH,
            confidence=0.9
        )
        actions_db.append(action)
        
        action_id = str(action.id)
        response = test_client.get(f"/api/v1/actions/{action_id}")
        
        assert response.status_code == 200
        action_data = response.json()
        assert action_data["id"] == action_id
        assert action_data["action_type"] == "terminate_pod"
        assert action_data["risk_level"] == "high"
    
    def test_get_action_not_found(self, test_client, reset_storage):
        """Test getting non-existent action"""
        from uuid import uuid4
        
        action_id = str(uuid4())
        response = test_client.get(f"/api/v1/actions/{action_id}")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
