"""
Unit tests for RLService
"""
import pytest
from app.services.rl_service import RLService
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.models.remediation_action import ActionType, RiskLevel


@pytest.mark.unit
@pytest.mark.asyncio
class TestRLService:
    """Test RLService"""
    
    @pytest.fixture
    def rl_service(self):
        """Create RLService instance"""
        return RLService()
    
    @pytest.mark.asyncio
    async def test_initialize(self, rl_service):
        """Test RL service initialization"""
        await rl_service.initialize()
        
        assert rl_service.initialized is True
    
    @pytest.mark.asyncio
    async def test_decide_action_critical_reverse_shell(self, rl_service):
        """Test decision for critical reverse shell threat"""
        await rl_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.REVERSE_SHELL,
            ml_score=0.9,
            description="Reverse shell detected"
        )
        
        action = await rl_service.decide_action(threat)
        
        assert action.action_type == ActionType.TERMINATE_POD
        assert action.risk_level == RiskLevel.HIGH
        assert action.confidence >= 0.9
        assert action.requires_confirmation is True
    
    @pytest.mark.asyncio
    async def test_decide_action_critical_other(self, rl_service):
        """Test decision for critical non-reverse-shell threat"""
        await rl_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.NETWORK_ANOMALY,
            ml_score=0.8,
            description="Network anomaly"
        )
        
        action = await rl_service.decide_action(threat)
        
        assert action.action_type == ActionType.ISOLATE_POD
        assert action.risk_level == RiskLevel.MEDIUM
        assert action.requires_confirmation is True
    
    @pytest.mark.asyncio
    async def test_decide_action_high_severity(self, rl_service):
        """Test decision for high severity threats"""
        await rl_service.initialize()
        
        # High severity reverse shell
        threat1 = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            ml_score=0.7
        )
        
        action1 = await rl_service.decide_action(threat1)
        assert action1.action_type == ActionType.ISOLATE_POD
        assert action1.risk_level == RiskLevel.MEDIUM
        
        # High severity container escape
        threat2 = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.CONTAINER_ESCAPE,
            ml_score=0.7
        )
        
        action2 = await rl_service.decide_action(threat2)
        assert action2.action_type == ActionType.ISOLATE_POD
        
        # High severity other
        threat3 = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.FILE_ANOMALY,
            ml_score=0.7
        )
        
        action3 = await rl_service.decide_action(threat3)
        assert action3.action_type == ActionType.ALERT
        assert action3.risk_level == RiskLevel.LOW
    
    @pytest.mark.asyncio
    async def test_decide_action_medium_severity(self, rl_service):
        """Test decision for medium severity threats"""
        await rl_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            ml_score=0.6
        )
        
        action = await rl_service.decide_action(threat)
        
        assert action.action_type == ActionType.ALERT
        assert action.risk_level == RiskLevel.LOW
        assert action.requires_confirmation is False
    
    @pytest.mark.asyncio
    async def test_decide_action_low_severity(self, rl_service):
        """Test decision for low severity threats"""
        await rl_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.LOW,
            threat_type=ThreatType.UNKNOWN,
            ml_score=0.3
        )
        
        action = await rl_service.decide_action(threat)
        
        assert action.action_type == ActionType.LOG
        assert action.risk_level == RiskLevel.LOW
        assert action.confidence == 0.5
    
    @pytest.mark.asyncio
    async def test_confidence_with_ml_score(self, rl_service):
        """Test that ML score boosts confidence"""
        await rl_service.initialize()
        
        threat_no_ml = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY
        )
        
        threat_with_ml = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            ml_score=0.9
        )
        
        action_no_ml = await rl_service.decide_action(threat_no_ml)
        action_with_ml = await rl_service.decide_action(threat_with_ml)
        
        assert action_with_ml.confidence > action_no_ml.confidence
    
    @pytest.mark.asyncio
    async def test_confirmation_requirements(self, rl_service):
        """Test that high/medium risk actions require confirmation"""
        await rl_service.initialize()
        
        # High risk
        threat_high = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.REVERSE_SHELL
        )
        action_high = await rl_service.decide_action(threat_high)
        assert action_high.requires_confirmation is True
        
        # Medium risk
        threat_medium = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.NETWORK_ANOMALY
        )
        action_medium = await rl_service.decide_action(threat_medium)
        assert action_medium.requires_confirmation is True
        
        # Low risk
        threat_low = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN
        )
        action_low = await rl_service.decide_action(threat_low)
        assert action_low.requires_confirmation is False
    
    @pytest.mark.asyncio
    async def test_action_threat_id(self, rl_service):
        """Test that action is linked to threat"""
        await rl_service.initialize()
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL
        )
        
        action = await rl_service.decide_action(threat)
        
        assert action.threat_id == threat.id
    
    @pytest.mark.asyncio
    async def test_health_check(self, rl_service):
        """Test health check"""
        await rl_service.initialize()
        
        health = await rl_service.health_check()
        
        assert health["status"] == "healthy"
        assert "agent_loaded" in health
