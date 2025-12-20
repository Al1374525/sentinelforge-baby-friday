"""
RL Service - Reinforcement Learning Agent
Uses stable-baselines3 for autonomous decision-making
"""
from typing import Optional
import os
from app.models.threat_event import ThreatEvent, ThreatType
from app.models.remediation_action import RemediationAction, ActionType, RiskLevel
from app.services.rl_env import CyberSecurityEnv
from app.utils.logging import get_logger

logger = get_logger(__name__)


class RLService:
    """Reinforcement Learning service for autonomous threat response"""
    
    def __init__(self):
        self.agent = None
        self.env = None
        self.initialized = False
        self.use_rl_agent = os.getenv("USE_RL_AGENT", "false").lower() == "true"
    
    async def initialize(self):
        """Initialize RL agent"""
        try:
            # Initialize environment
            self.env = CyberSecurityEnv()
            
            # Try to load trained RL agent if available
            if self.use_rl_agent:
                try:
                    from stable_baselines3 import PPO
                    model_path = os.getenv("RL_MODEL_PATH", "models/rl_agent.zip")
                    if os.path.exists(model_path):
                        self.agent = PPO.load(model_path, env=self.env)
                        logger.info("RL Service initialized (trained PPO agent)")
                    else:
                        logger.warning("RL model not found, using rule-based agent")
                        self.use_rl_agent = False
                except ImportError:
                    logger.warning("stable-baselines3 not available, using rule-based agent")
                    self.use_rl_agent = False
                except Exception as e:
                    logger.warning(f"Error loading RL agent: {e}, using rule-based agent", exc_info=True)
                    self.use_rl_agent = False
            
            if not self.use_rl_agent:
                logger.info("RL Service initialized (rule-based agent)")
            
            self.initialized = True
        except Exception as e:
            logger.error(f"Error initializing RL service: {e}", exc_info=True)
            self.initialized = False
    
    async def decide_action(self, threat: ThreatEvent) -> RemediationAction:
        """
        Decide on remediation action based on threat
        Uses RL agent if available, otherwise falls back to rule-based logic
        """
        if self.use_rl_agent and self.agent is not None:
            # Use RL agent for decision
            return await self._decide_with_rl(threat)
        else:
            # Fall back to rule-based logic
            return await self._decide_with_rules(threat)
    
    async def _decide_with_rl(self, threat: ThreatEvent) -> RemediationAction:
        """Decide action using trained RL agent"""
        try:
            # Convert threat to state
            state = self.env._threat_to_state(threat)
            
            # Get action from agent
            action_int, _ = self.agent.predict(state, deterministic=True)
            action_type = self.env._action_to_type(int(action_int))
            
            # Calculate confidence based on agent's action probability
            # For now, use ML score and threat characteristics
            confidence = 0.7
            if threat.ml_score:
                confidence = min(1.0, 0.7 + (threat.ml_score * 0.3))
            
            # Determine risk level based on action type
            risk_level = RiskLevel.LOW
            if action_type in [ActionType.TERMINATE_POD, ActionType.ISOLATE_POD]:
                risk_level = RiskLevel.HIGH if threat.severity.value == "critical" else RiskLevel.MEDIUM
            elif action_type == ActionType.ESCALATE:
                risk_level = RiskLevel.HIGH
            
            action = RemediationAction(
                threat_id=threat.id,
                action_type=action_type,
                risk_level=risk_level,
                confidence=confidence,
                ml_score=threat.ml_score,
                requires_confirmation=(risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH])
            )
            
            return action
        except Exception as e:
            logger.error(f"Error in RL decision: {e}, falling back to rules", exc_info=True)
            return await self._decide_with_rules(threat)
    
    async def _decide_with_rules(self, threat: ThreatEvent) -> RemediationAction:
        """Decide action using rule-based logic"""
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
