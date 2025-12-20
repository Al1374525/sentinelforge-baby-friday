"""
Integration tests for threat processing pipeline
"""
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from app.services.falco_processor import FalcoProcessor
from app.services.ml_service import MLService
from app.services.rl_service import RLService
from app.services.remediation_service import RemediationService
from app.models.threat_event import ThreatSeverity, ThreatType
from app.models.remediation_action import ActionType, RiskLevel
from tests.fixtures.falco_events import REVERSE_SHELL_EVENT


@pytest.mark.integration
@pytest.mark.asyncio
class TestThreatPipeline:
    """Test complete threat processing pipeline"""
    
    @pytest.fixture
    def services(self):
        """Initialize all services"""
        return {
            'falco_processor': FalcoProcessor(),
            'ml_service': MLService(),
            'rl_service': RLService(),
            'remediation_service': RemediationService()
        }
    
    @pytest.mark.asyncio
    async def test_complete_pipeline(self, services, reset_storage):
        """Test complete threat processing pipeline"""
        # Initialize services
        await services['ml_service'].initialize()
        await services['rl_service'].initialize()
        await services['remediation_service'].initialize()
        
        # Process Falco event
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock) as mock_broadcast:
            threat = await services['falco_processor'].process_event(REVERSE_SHELL_EVENT)
            
            assert threat is not None
            assert threat.severity == ThreatSeverity.HIGH
            assert threat.threat_type == ThreatType.REVERSE_SHELL
            
            # Verify WebSocket broadcast
            mock_broadcast.assert_called_once()
        
        # Run ML anomaly detection
        ml_score = await services['ml_service'].detect_anomaly(threat)
        threat.ml_score = ml_score
        
        assert 0.0 <= ml_score <= 1.0
        
        # Get RL decision
        action = await services['rl_service'].decide_action(threat)
        
        assert action is not None
        assert action.threat_id == threat.id
        assert action.action_type == ActionType.TERMINATE_POD
        assert action.risk_level == RiskLevel.HIGH
        assert action.ml_score == ml_score
        
        # Verify threat stored
        from app.storage import threats_db
        assert threat in threats_db
    
    @pytest.mark.asyncio
    async def test_pipeline_with_auto_execution(self, services, reset_storage):
        """Test pipeline with auto-execution of low-risk action"""
        await services['ml_service'].initialize()
        await services['rl_service'].initialize()
        await services['remediation_service'].initialize()
        
        # Create a threat that will result in low-risk action
        from app.models.threat_event import ThreatEvent
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            source_pod="test-pod",
            source_namespace="default",
            ml_score=0.6,
            description="Network anomaly"
        )
        
        # Get RL decision (should be ALERT with LOW risk)
        action = await services['rl_service'].decide_action(threat)
        action.confidence = 0.9  # High confidence
        
        # Execute action (should execute automatically)
        await services['remediation_service'].execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
        
        # Verify action stored
        from app.storage import actions_db
        assert action in actions_db
    
    @pytest.mark.asyncio
    async def test_pipeline_error_propagation(self, services, reset_storage):
        """Test error propagation through pipeline"""
        await services['ml_service'].initialize()
        await services['rl_service'].initialize()
        
        # Process invalid event
        invalid_event = {"invalid": "data"}
        
        threat = await services['falco_processor'].process_event(invalid_event)
        
        # Should handle gracefully (returns None or creates threat with defaults)
        # Pipeline should continue even if one step fails
        if threat:
            # If threat created, continue pipeline
            ml_score = await services['ml_service'].detect_anomaly(threat)
            action = await services['rl_service'].decide_action(threat)
            assert action is not None
    
    @pytest.mark.asyncio
    async def test_pipeline_websocket_broadcast(self, services, reset_storage):
        """Test that WebSocket broadcast is triggered"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock) as mock_broadcast:
            threat = await services['falco_processor'].process_event(REVERSE_SHELL_EVENT)
            
            assert threat is not None
            
            # Verify broadcast was called with correct data
            mock_broadcast.assert_called_once()
            broadcast_data = mock_broadcast.call_args[0][0]
            
            assert broadcast_data["type"] == "threat_detected"
            assert broadcast_data["threat_id"] == str(threat.id)
            assert broadcast_data["severity"] == threat.severity.value
            assert broadcast_data["threat_type"] == threat.threat_type.value
    
    @pytest.mark.asyncio
    async def test_pipeline_ml_score_influence(self, services, reset_storage):
        """Test that ML score influences RL confidence"""
        await services['ml_service'].initialize()
        await services['rl_service'].initialize()
        
        threat1 = await services['falco_processor'].process_event(REVERSE_SHELL_EVENT)
        ml_score1 = await services['ml_service'].detect_anomaly(threat1)
        threat1.ml_score = ml_score1
        
        action1 = await services['rl_service'].decide_action(threat1)
        confidence1 = action1.confidence
        
        # Create threat with higher ML score
        threat2 = await services['falco_processor'].process_event(REVERSE_SHELL_EVENT)
        threat2.ml_score = 0.95  # Higher ML score
        action2 = await services['rl_service'].decide_action(threat2)
        confidence2 = action2.confidence
        
        # Higher ML score should boost confidence
        assert confidence2 >= confidence1
