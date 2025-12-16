"""
ML Service - Anomaly Detection
Uses scikit-learn for threat detection
"""
from typing import Optional
import numpy as np
from app.models.threat_event import ThreatEvent


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
            
            # For prototype: train on dummy data
            # In production, this would be trained on historical data
            dummy_features = np.random.rand(100, 10)  # 100 samples, 10 features
            self.model.fit(dummy_features)
            
            self.initialized = True
            print("✅ ML Service initialized (Isolation Forest)")
        except ImportError:
            print("⚠️  scikit-learn not installed, ML service running in mock mode")
            self.initialized = False
        except Exception as e:
            print(f"⚠️  Error initializing ML service: {e}")
            self.initialized = False
    
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
            print(f"⚠️  Error in ML detection: {e}")
            return 0.5  # Default neutral score
    
    def _extract_features(self, threat: ThreatEvent) -> list:
        """
        Extract features from threat event for ML model
        This is a simplified version - in production, would extract more features
        """
        features = [
            len(threat.falco_output),  # Output length
            1.0 if threat.source_pod else 0.0,  # Has pod
            1.0 if threat.source_user else 0.0,  # Has user
            len(threat.falco_rule) if threat.falco_rule else 0,  # Rule length
            hash(threat.threat_type.value) % 100 / 100.0,  # Threat type hash
            hash(threat.severity.value) % 100 / 100.0,  # Severity hash
            0.5,  # Placeholder features
            0.5,
            0.5,
            0.5
        ]
        return features
    
    async def health_check(self) -> dict:
        """Health check for ML service"""
        return {
            "status": "healthy" if self.initialized else "degraded",
            "model_loaded": self.model is not None
        }
