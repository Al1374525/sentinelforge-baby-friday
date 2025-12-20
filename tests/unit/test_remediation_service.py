"""
Unit tests for RemediationService
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from app.services.remediation_service import RemediationService
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.models.remediation_action import RemediationAction, ActionType, RiskLevel


@pytest.mark.unit
@pytest.mark.asyncio
class TestRemediationService:
    """Test RemediationService"""
    
    @pytest.fixture
    def remediation_service(self):
        """Create RemediationService instance"""
        return RemediationService()
    
    @pytest.mark.asyncio
    async def test_initialize_with_k8s(self, remediation_service, mock_k8s_client):
        """Test initialization with Kubernetes available"""
        with patch('app.services.remediation_service.config.load_kube_config'):
            with patch('app.services.remediation_service.client.CoreV1Api', return_value=mock_k8s_client['core_v1']):
                await remediation_service.initialize()
                
                assert remediation_service.initialized is True
                assert remediation_service.k8s_client is not None
    
    @pytest.mark.asyncio
    async def test_initialize_without_k8s(self, remediation_service):
        """Test initialization without Kubernetes"""
        with patch('app.services.remediation_service.config.load_kube_config', side_effect=Exception("No kubeconfig")):
            await remediation_service.initialize()
            
            assert remediation_service.initialized is False
            assert remediation_service.k8s_client is None
    
    @pytest.mark.asyncio
    async def test_execute_action_requires_confirmation(self, remediation_service, reset_storage):
        """Test that actions requiring confirmation are not executed"""
        await remediation_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            source_namespace="default"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.HIGH,
            requires_confirmation=True,
            confidence=0.9
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is False
        assert action.success is None
    
    @pytest.mark.asyncio
    async def test_execute_terminate_pod_simulated(self, remediation_service, reset_storage):
        """Test pod termination in simulated mode"""
        remediation_service.initialized = False
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            source_namespace="default"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.9
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
    
    @pytest.mark.asyncio
    async def test_execute_terminate_pod_real(self, remediation_service, mock_k8s_client, reset_storage):
        """Test pod termination with real K8s client"""
        remediation_service.k8s_client = mock_k8s_client['core_v1']
        remediation_service.initialized = True
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            source_namespace="default"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.9
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
        mock_k8s_client['core_v1'].delete_namespaced_pod.assert_called_once_with(
            name="test-pod",
            namespace="default",
            grace_period_seconds=0
        )
    
    @pytest.mark.asyncio
    async def test_execute_isolate_pod_simulated(self, remediation_service, reset_storage):
        """Test pod isolation in simulated mode"""
        remediation_service.initialized = False
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.CONTAINER_ESCAPE,
            source_pod="test-pod",
            source_namespace="default"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ISOLATE_POD,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.8
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
    
    @pytest.mark.asyncio
    async def test_execute_alert(self, remediation_service, reset_storage):
        """Test alert action"""
        await remediation_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            description="Test alert"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ALERT,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.7
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
    
    @pytest.mark.asyncio
    async def test_execute_log(self, remediation_service, reset_storage):
        """Test log action"""
        await remediation_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.LOW,
            threat_type=ThreatType.UNKNOWN,
            description="Test log"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.LOG,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.5
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
    
    @pytest.mark.asyncio
    async def test_execute_monitor(self, remediation_service, reset_storage):
        """Test monitor action (always succeeds)"""
        await remediation_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.LOW,
            threat_type=ThreatType.UNKNOWN
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.MONITOR,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.3
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is True
    
    @pytest.mark.asyncio
    async def test_execute_action_error_handling(self, remediation_service, mock_k8s_client, reset_storage):
        """Test error handling during action execution"""
        remediation_service.k8s_client = mock_k8s_client['core_v1']
        remediation_service.initialized = True
        
        # Make K8s call raise exception
        mock_k8s_client['core_v1'].delete_namespaced_pod.side_effect = Exception("K8s error")
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            source_namespace="default"
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.TERMINATE_POD,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.9
        )
        
        await remediation_service.execute_action(action, threat)
        
        assert action.executed is True
        assert action.success is False
        assert action.error_message == "K8s error"
    
    @pytest.mark.asyncio
    async def test_action_storage(self, remediation_service, reset_storage):
        """Test that actions are stored"""
        from app.storage import actions_db
        
        await remediation_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY
        )
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=ActionType.ALERT,
            risk_level=RiskLevel.LOW,
            requires_confirmation=False,
            confidence=0.7
        )
        
        initial_count = len(actions_db)
        await remediation_service.execute_action(action, threat)
        
        assert len(actions_db) == initial_count + 1
        assert action in actions_db
    
    @pytest.mark.asyncio
    async def test_health_check(self, remediation_service):
        """Test health check"""
        remediation_service.initialized = True
        remediation_service.k8s_client = Mock()
        
        health = await remediation_service.health_check()
        
        assert health["status"] == "healthy"
        assert health["k8s_available"] is True
    
    @pytest.mark.asyncio
    async def test_health_check_degraded(self, remediation_service):
        """Test health check when degraded"""
        remediation_service.initialized = False
        remediation_service.k8s_client = None
        
        health = await remediation_service.health_check()
        
        assert health["status"] == "degraded"
        assert health["k8s_available"] is False
