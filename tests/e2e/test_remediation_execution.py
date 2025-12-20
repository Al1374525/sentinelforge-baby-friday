"""
End-to-end tests for remediation execution
"""
import pytest
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.models.remediation_action import RemediationAction, ActionType, RiskLevel
from app.storage import threats_db, actions_db


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.k8s
class TestRemediationExecution:
    """End-to-end tests for remediation execution"""
    
    def test_auto_execution_low_risk_action(self, test_client, reset_storage):
        """Test automatic execution of low-risk actions"""
        # Create a threat that will result in low-risk action
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            source_pod="test-pod",
            source_namespace="default",
            ml_score=0.6,
            description="Network anomaly"
        )
        threats_db.append(threat)
        
        # Create low-risk action with high confidence
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ALERT,
            risk_level=RiskLevel.LOW,
            confidence=0.9,  # High confidence
            requires_confirmation=False
        )
        
        # Execute action via remediation service
        from app.services.remediation_service import RemediationService
        remediation_service = RemediationService()
        
        # Mock K8s client to avoid actual K8s calls
        remediation_service.initialized = False  # Simulated mode
        
        import asyncio
        asyncio.run(remediation_service.execute_action(action, threat))
        
        assert action.executed is True
        assert action.success is True
        
        # Verify action stored
        assert action in actions_db
    
    def test_confirmation_required_high_risk(self, test_client, reset_storage):
        """Test that high-risk actions require confirmation"""
        threat = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="evil-pod",
            source_namespace="default",
            ml_score=0.95,
            description="Reverse shell detected"
        )
        threats_db.append(threat)
        
        # Create high-risk action
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            requires_confirmation=True
        )
        
        # Execute action via remediation service
        from app.services.remediation_service import RemediationService
        remediation_service = RemediationService()
        remediation_service.initialized = False  # Simulated mode
        
        import asyncio
        asyncio.run(remediation_service.execute_action(action, threat))
        
        # Should not execute automatically
        assert action.executed is False
        assert action.success is None
    
    def test_remediation_action_storage(self, test_client, reset_storage):
        """Test that remediation actions are stored and retrievable"""
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.CONTAINER_ESCAPE,
            source_pod="escape-pod",
            source_namespace="default"
        )
        threats_db.append(threat)
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ISOLATE_POD,
            risk_level=RiskLevel.MEDIUM,
            confidence=0.8,
            requires_confirmation=True
        )
        actions_db.append(action)
        
        # Verify action can be retrieved via API
        response = test_client.get("/api/v1/actions")
        assert response.status_code == 200
        
        actions = response.json()
        assert len(actions) > 0
        
        # Find our action
        found_action = next((a for a in actions if a["id"] == str(action.id)), None)
        assert found_action is not None
        assert found_action["threat_id"] == str(threat.id)
        assert found_action["action_type"] == "isolate_pod"
