"""
Reinforcement Learning Environment for Cybersecurity
Gymnasium-compatible environment for training RL agent
"""
import numpy as np
from typing import Dict, Tuple, Any, Optional
from gymnasium import Env, spaces
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.models.remediation_action import ActionType, RiskLevel


class CyberSecurityEnv(Env):
    """
    Custom Gymnasium environment for cybersecurity threat response
    
    State: Threat characteristics (severity, type, ML score, etc.)
    Action: Remediation action to take
    Reward: Based on action effectiveness and risk
    """
    
    metadata = {"render_modes": ["human"], "render_fps": 4}
    
    def __init__(self):
        super().__init__()
        
        # Action space: 8 possible actions
        # 0: MONITOR, 1: LOG, 2: ALERT, 3: ISOLATE_POD, 
        # 4: TERMINATE_POD, 5: BLOCK_NETWORK, 6: TERMINATE_PROCESS, 7: ESCALATE
        self.action_space = spaces.Discrete(8)
        
        # State space: [severity, threat_type, ml_score, has_pod, has_user, confidence]
        # Normalized to [0, 1] range
        self.observation_space = spaces.Box(
            low=0.0,
            high=1.0,
            shape=(6,),
            dtype=np.float32
        )
        
        # Current state
        self.state = None
        self.current_threat = None
        
    def reset(self, seed: Optional[int] = None, options: Optional[dict] = None) -> Tuple[np.ndarray, Dict]:
        """Reset environment and return initial observation"""
        super().reset(seed=seed)
        
        # Generate a random threat for training
        self.current_threat = self._generate_random_threat()
        self.state = self._threat_to_state(self.current_threat)
        
        return self.state.astype(np.float32), {}
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """Execute action and return (observation, reward, terminated, truncated, info)"""
        if self.current_threat is None:
            raise ValueError("Environment not reset")
        
        # Convert action to ActionType
        action_type = self._action_to_type(action)
        
        # Calculate reward based on action appropriateness
        reward = self._calculate_reward(action_type, self.current_threat)
        
        # Determine if episode is done (action executed)
        terminated = action_type in [ActionType.TERMINATE_POD, ActionType.ISOLATE_POD, ActionType.ESCALATE]
        
        # Generate next threat (for continuous training)
        self.current_threat = self._generate_random_threat()
        self.state = self._threat_to_state(self.current_threat)
        
        truncated = False
        info = {
            "action": action_type.value,
            "threat_type": self.current_threat.threat_type.value,
            "severity": self.current_threat.severity.value
        }
        
        return self.state.astype(np.float32), reward, terminated, truncated, info
    
    def _threat_to_state(self, threat: ThreatEvent) -> np.ndarray:
        """Convert threat to state vector"""
        # Severity encoding
        severity_map = {
            ThreatSeverity.LOW: 0.25,
            ThreatSeverity.MEDIUM: 0.50,
            ThreatSeverity.HIGH: 0.75,
            ThreatSeverity.CRITICAL: 1.0
        }
        severity_val = severity_map.get(threat.severity, 0.5)
        
        # Threat type encoding
        threat_type_map = {
            ThreatType.REVERSE_SHELL: 1.0,
            ThreatType.CONTAINER_ESCAPE: 0.9,
            ThreatType.PRIVILEGE_ESCALATION: 0.8,
            ThreatType.MALICIOUS_PROCESS: 0.7,
            ThreatType.NETWORK_ANOMALY: 0.5,
            ThreatType.FILE_ANOMALY: 0.4,
            ThreatType.UNAUTHORIZED_ACCESS: 0.3,
            ThreatType.UNKNOWN: 0.2
        }
        threat_type_val = threat_type_map.get(threat.threat_type, 0.2)
        
        # ML score (normalized)
        ml_score = threat.ml_score if threat.ml_score else 0.5
        
        # Has pod
        has_pod = 1.0 if threat.source_pod else 0.0
        
        # Has user
        has_user = 1.0 if threat.source_user else 0.0
        
        # Confidence (from threat or default)
        confidence = threat.confidence if threat.confidence else 0.5
        
        return np.array([
            severity_val,
            threat_type_val,
            ml_score,
            has_pod,
            has_user,
            confidence
        ])
    
    def _action_to_type(self, action: int) -> ActionType:
        """Convert action integer to ActionType"""
        action_map = {
            0: ActionType.MONITOR,
            1: ActionType.LOG,
            2: ActionType.ALERT,
            3: ActionType.ISOLATE_POD,
            4: ActionType.TERMINATE_POD,
            5: ActionType.BLOCK_NETWORK,
            6: ActionType.TERMINATE_PROCESS,
            7: ActionType.ESCALATE
        }
        return action_map.get(action, ActionType.MONITOR)
    
    def _calculate_reward(self, action: ActionType, threat: ThreatEvent) -> float:
        """
        Calculate reward based on action appropriateness
        
        Reward structure:
        - High reward for appropriate actions
        - Negative reward for over-reaction (terminating low-risk threats)
        - Negative reward for under-reaction (monitoring critical threats)
        - Small penalty for escalation (prefer autonomous action when safe)
        """
        severity = threat.severity
        threat_type = threat.threat_type
        
        # Base rewards for actions
        action_rewards = {
            ActionType.MONITOR: 0.1,
            ActionType.LOG: 0.2,
            ActionType.ALERT: 0.5,
            ActionType.ISOLATE_POD: 0.7,
            ActionType.TERMINATE_POD: 0.9,
            ActionType.BLOCK_NETWORK: 0.6,
            ActionType.TERMINATE_PROCESS: 0.8,
            ActionType.ESCALATE: 0.3  # Penalty for requiring human
        }
        
        base_reward = action_rewards.get(action, 0.0)
        
        # Adjust based on threat severity
        if severity == ThreatSeverity.CRITICAL:
            if action in [ActionType.TERMINATE_POD, ActionType.ISOLATE_POD]:
                reward = 1.0  # Correct action
            elif action == ActionType.MONITOR:
                reward = -1.0  # Under-reaction
            else:
                reward = 0.3  # Suboptimal
        elif severity == ThreatSeverity.HIGH:
            if action in [ActionType.ISOLATE_POD, ActionType.ALERT]:
                reward = 0.8
            elif action == ActionType.TERMINATE_POD:
                reward = 0.6  # Slightly over-reactive
            elif action == ActionType.MONITOR:
                reward = -0.5
            else:
                reward = base_reward
        elif severity == ThreatSeverity.MEDIUM:
            if action == ActionType.ALERT:
                reward = 0.7
            elif action in [ActionType.TERMINATE_POD, ActionType.ISOLATE_POD]:
                reward = -0.3  # Over-reaction
            else:
                reward = base_reward
        else:  # LOW
            if action in [ActionType.MONITOR, ActionType.LOG]:
                reward = 0.6
            elif action in [ActionType.TERMINATE_POD, ActionType.ISOLATE_POD]:
                reward = -0.8  # Severe over-reaction
            else:
                reward = base_reward
        
        # Bonus for reverse shell detection
        if threat_type == ThreatType.REVERSE_SHELL and action == ActionType.TERMINATE_POD:
            reward += 0.2
        
        # Normalize reward to [-1, 1]
        return np.clip(reward, -1.0, 1.0)
    
    def _generate_random_threat(self) -> ThreatEvent:
        """Generate a random threat for training"""
        import random
        
        severities = list(ThreatSeverity)
        threat_types = list(ThreatType)
        
        threat = ThreatEvent(
            severity=random.choice(severities),
            threat_type=random.choice(threat_types),
            source_pod=f"pod-{random.randint(1, 100)}" if random.random() > 0.2 else None,
            source_user=f"user-{random.randint(1, 10)}" if random.random() > 0.3 else None,
            ml_score=random.uniform(0.0, 1.0),
            confidence=random.uniform(0.0, 1.0),
            description="Training threat"
        )
        
        return threat
