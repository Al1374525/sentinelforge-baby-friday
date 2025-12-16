"""
RL Service - Reinforcement Learning Agent
Uses stable-baselines3 for autonomous decision-making
"""
from typing import Optional
from app.models.threat_event import ThreatEvent
from app.models.remediation_action import RemediationAction, ActionType, RiskLevel


class RLService:
    """Reinforcement Learning service for autonomous threat response"""
    
    def __init__(self):
        self.agent = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize RL agent"""
        try:
            # Lazy import to avoid requiring stable-baselines3 at startup
            # For prototype, we'll use a simple rule-based agent
            # In production, this would load a trained PPO agent
            
            self.initialized = True
            print("✅ RL Service initialized (rule-based agent for prototype)")
        except Exception as e:
            print(f"⚠️  Error initializing RL service: {e}")
            self.initialized = False
    
    async def decide_action(self, threat: ThreatEvent) -> RemediationAction:
        """
        Decide on remediation action based on threat
        Uses RL agent (or rule-based logic for prototype)
        """
        # For prototype: rule-based decision making
        # In production: RL agent would make this decision
        
        action_type = ActionType.MONITOR
        risk_level = RiskLevel.LOW
        confidence = 0.5
        
        # Rule-based logic (Decision: Option B - Moderate)
        if threat.severity.value == "critical":
            if threat.threat_type == ThreatType.REVERSE_SHELL:
                action_type = ActionType.TERMINATE_POD
                risk_level = RiskLevel.HIGH  # Requires confirmation
                confidence = 0.9
            else:
                action_type = ActionType.ISOLATE_POD
                risk_level = RiskLevel.MEDIUM
                confidence = 0.8
        elif threat.severity.value == "high":
            if threat.threat_type in [ThreatType.REVERSE_SHELL, ThreatType.CONTAINER_ESCAPE]:
                action_type = ActionType.ISOLATE_POD
                risk_level = RiskLevel.MEDIUM
                confidence = 0.75
            else:
                action_type = ActionType.ALERT
                risk_level = RiskLevel.LOW
                confidence = 0.7
        elif threat.severity.value == "medium":
            action_type = ActionType.ALERT
            risk_level = RiskLevel.LOW
            confidence = 0.6
        else:  # low
            action_type = ActionType.LOG
            risk_level = RiskLevel.LOW
            confidence = 0.5
        
        # Boost confidence with ML score if available
        if threat.ml_score:
            confidence = min(1.0, confidence + (threat.ml_score * 0.2))
        
        action = RemediationAction(
            threat_id=threat.id,
            action_type=action_type,
            risk_level=risk_level,
            confidence=confidence,
            ml_score=threat.ml_score,
            requires_confirmation=(risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH])
        )
        
        return action
    
    async def health_check(self) -> dict:
        """Health check for RL service"""
        return {
            "status": "healthy" if self.initialized else "degraded",
            "agent_loaded": self.agent is not None if hasattr(self, 'agent') else False
        }
