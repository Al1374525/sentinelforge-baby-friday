"""
ML Service - Anomaly Detection
Uses scikit-learn for threat detection
"""
from typing import Optional
import numpy as np
from app.models.threat_event import ThreatEvent
from app.utils.logging import get_logger

logger = get_logger(__name__)


class MLService:
    """Machine Learning service for anomaly detection"""
    
    def __init__(self):
        self.model = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize ML models"""
        try:
            # Lazy import to avoid requiring scikit-learn at startup if not installed
            from sklearn.ensemble import IsolationForest
            
            # Initialize Isolation Forest model
            # Contamination: expected proportion of anomalies (5%)
            self.model = IsolationForest(
                contamination=0.05,
                random_state=42,
                n_estimators=100
            )
            
            # Generate synthetic training data based on threat characteristics
            # This simulates real threat patterns better than pure random data
            training_features = self._generate_training_data()
            self.model.fit(training_features)
            
            self.initialized = True
            logger.info("ML Service initialized (Isolation Forest)")
        except ImportError:
            logger.warning("scikit-learn not installed, ML service running in mock mode")
            self.initialized = False
        except Exception as e:
            logger.error(f"Error initializing ML service: {e}", exc_info=True)
            self.initialized = False
    
    def _generate_training_data(self) -> np.ndarray:
        """
        Generate synthetic training data that simulates real threat patterns
        Creates a mix of normal and anomalous patterns
        """
        np.random.seed(42)
        num_samples = 200
        num_features = 15
        
        features = []
        
        # Generate normal patterns (80% of data)
        for _ in range(int(num_samples * 0.8)):
            feature_vector = [
                np.random.uniform(50, 200),  # Output length (normal range)
                1.0,  # Has pod
                np.random.choice([0.0, 1.0], p=[0.3, 0.7]),  # Has user
                np.random.uniform(10, 50),  # Rule length (normal)
                np.random.uniform(0.2, 0.5),  # Threat type hash (normal)
                np.random.uniform(0.2, 0.4),  # Severity hash (low-medium)
                np.random.uniform(0.0, 0.3),  # Network activity score
                np.random.uniform(0.0, 0.2),  # File access score
                np.random.uniform(0.0, 0.2),  # Process anomaly score
                np.random.uniform(0.0, 0.1),  # Container escape score
                np.random.uniform(0.0, 0.2),  # Privilege escalation score
                np.random.uniform(0.0, 0.1),  # Shell activity score
                np.random.uniform(0.0, 0.2),  # Time-based feature
                np.random.uniform(0.0, 0.1),  # Frequency feature
                np.random.uniform(0.0, 0.2),  # Context feature
            ]
            features.append(feature_vector)
        
        # Generate anomalous patterns (20% of data) - these should be detected as anomalies
        for _ in range(int(num_samples * 0.2)):
            feature_vector = [
                np.random.uniform(300, 1000),  # Very long output (suspicious)
                1.0,  # Has pod
                1.0,  # Has user (often root in attacks)
                np.random.uniform(5, 15),  # Short rule name (custom rules)
                np.random.uniform(0.7, 0.9),  # Threat type hash (high-risk types)
                np.random.uniform(0.7, 0.95),  # Severity hash (high-critical)
                np.random.uniform(0.6, 1.0),  # High network activity
                np.random.uniform(0.5, 1.0),  # High file access
                np.random.uniform(0.6, 1.0),  # High process anomaly
                np.random.uniform(0.5, 1.0),  # Container escape attempts
                np.random.uniform(0.5, 1.0),  # Privilege escalation
                np.random.uniform(0.7, 1.0),  # Shell activity (reverse shells)
                np.random.uniform(0.5, 1.0),  # Time-based anomaly
                np.random.uniform(0.6, 1.0),  # High frequency
                np.random.uniform(0.5, 1.0),  # Suspicious context
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    async def detect_anomaly(self, threat: ThreatEvent) -> float:
        """
        Detect if threat is an anomaly using ML model
        Returns anomaly score (0-1, higher = more anomalous)
        """
        if not self.initialized or not self.model:
            # Mock mode: return score based on severity
            severity_scores = {
                "low": 0.3,
                "medium": 0.6,
                "high": 0.85,
                "critical": 0.95
            }
            return severity_scores.get(threat.severity.value, 0.5)
        
        try:
            # Extract features from threat event
            features = self._extract_features(threat)
            
            # Predict anomaly score
            # Isolation Forest returns -1 (anomaly) or 1 (normal)
            prediction = self.model.predict([features])[0]
            decision_score = self.model.decision_function([features])[0]
            
            # Convert to 0-1 score (higher = more anomalous)
            # Normalize decision score (typically ranges from -0.5 to 0.5)
            anomaly_score = max(0.0, min(1.0, (decision_score + 0.5)))
            
            return float(anomaly_score)
        
        except Exception as e:
            logger.error(f"Error in ML detection: {e}", exc_info=True)
            return 0.5  # Default neutral score
    
    def _extract_features(self, threat: ThreatEvent) -> list:
        """
        Extract features from threat event for ML model
        Enhanced feature extraction with more meaningful features
        """
        # Normalize output length (typical range: 50-500 chars)
        output_length = len(threat.falco_output) if threat.falco_output else 0
        normalized_output_length = min(output_length / 500.0, 1.0)
        
        # Rule length (shorter rules often indicate custom/suspicious rules)
        rule_length = len(threat.falco_rule) if threat.falco_rule else 0
        normalized_rule_length = min(rule_length / 100.0, 1.0)
        
        # Threat type encoding (higher values for more dangerous types)
        threat_type_scores = {
            "reverse_shell": 0.95,
            "container_escape": 0.90,
            "privilege_escalation": 0.85,
            "malicious_process": 0.80,
            "network_anomaly": 0.60,
            "file_anomaly": 0.50,
            "unauthorized_access": 0.40,
            "unknown": 0.30
        }
        threat_type_score = threat_type_scores.get(threat.threat_type.value, 0.3)
        
        # Severity encoding
        severity_scores = {
            "critical": 0.95,
            "high": 0.75,
            "medium": 0.50,
            "low": 0.25
        }
        severity_score = severity_scores.get(threat.severity.value, 0.5)
        
        # Network activity indicators
        network_keywords = ["nc ", "netcat", "connect", "socket", "port", "tcp", "udp"]
        network_activity = 1.0 if any(kw in threat.falco_output.lower() for kw in network_keywords) else 0.0
        
        # File access indicators
        file_keywords = ["/etc/passwd", "/etc/shadow", "/root", "secret", "credential", "password"]
        file_access = 1.0 if any(kw in threat.falco_output.lower() for kw in file_keywords) else 0.0
        
        # Process anomaly indicators
        process_keywords = ["setuid", "setgid", "ptrace", "inject", "fork"]
        process_anomaly = 1.0 if any(kw in threat.falco_output.lower() for kw in process_keywords) else 0.0
        
        # Container escape indicators
        escape_keywords = ["/proc/sys", "/sys", "chroot", "mount", "host"]
        container_escape = 1.0 if any(kw in threat.falco_output.lower() for kw in escape_keywords) else 0.0
        
        # Privilege escalation indicators
        priv_keywords = ["sudo", "su ", "pkexec", "doas"]
        privilege_escalation = 1.0 if any(kw in threat.falco_output.lower() for kw in priv_keywords) else 0.0
        
        # Shell activity indicators
        shell_keywords = ["bash -i", "/bin/sh", "/bin/bash", "shell", "sh -c"]
        shell_activity = 1.0 if any(kw in threat.falco_output.lower() for kw in shell_keywords) else 0.0
        
        # Time-based feature (hour of day - attacks often happen off-hours)
        # For now, use a placeholder
        time_feature = 0.5  # Could extract from threat.detected_at
        
        # Frequency feature (how often this pod/user appears)
        # For now, use a placeholder
        frequency_feature = 0.3  # Would require historical data
        
        # Context feature (namespace, container type, etc.)
        # Production namespaces are typically less suspicious
        suspicious_namespaces = ["default", "kube-system"]
        context_feature = 0.7 if threat.source_namespace in suspicious_namespaces else 0.3
        
        features = [
            normalized_output_length,
            1.0 if threat.source_pod else 0.0,  # Has pod
            1.0 if threat.source_user else 0.0,  # Has user
            normalized_rule_length,
            threat_type_score,
            severity_score,
            network_activity,
            file_access,
            process_anomaly,
            container_escape,
            privilege_escalation,
            shell_activity,
            time_feature,
            frequency_feature,
            context_feature
        ]
        
        return features
    
    async def health_check(self) -> dict:
        """Health check for ML service"""
        return {
            "status": "healthy" if self.initialized else "degraded",
            "model_loaded": self.model is not None
        }
