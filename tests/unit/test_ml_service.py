"""
Unit tests for MLService
"""
import pytest
import numpy as np
from unittest.mock import patch, MagicMock
from app.services.ml_service import MLService
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType


@pytest.mark.unit
@pytest.mark.asyncio
class TestMLService:
    """Test MLService"""
    
    @pytest.fixture
    def ml_service(self):
        """Create MLService instance"""
        return MLService()
    
    @pytest.mark.asyncio
    async def test_initialize_with_scikit_learn(self, ml_service):
        """Test ML service initialization with scikit-learn available"""
        with patch('app.services.ml_service.IsolationForest') as mock_if:
            mock_model = MagicMock()
            mock_if.return_value = mock_model
            
            await ml_service.initialize()
            
            assert ml_service.initialized is True
            assert ml_service.model is not None
            mock_model.fit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_initialize_without_scikit_learn(self, ml_service):
        """Test ML service initialization without scikit-learn"""
        with patch('builtins.__import__', side_effect=ImportError("No module named 'sklearn'")):
            await ml_service.initialize()
            
            assert ml_service.initialized is False
            assert ml_service.model is None
    
    @pytest.mark.asyncio
    async def test_detect_anomaly_mock_mode(self, ml_service):
        """Test anomaly detection in mock mode"""
        ml_service.initialized = False
        
        threat = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.REVERSE_SHELL,
            description="Test threat"
        )
        
        score = await ml_service.detect_anomaly(threat)
        
        assert 0.0 <= score <= 1.0
        assert score == 0.95  # Critical severity should get 0.95 in mock mode
    
    @pytest.mark.asyncio
    async def test_detect_anomaly_severity_scores(self, ml_service):
        """Test that different severities get different mock scores"""
        ml_service.initialized = False
        
        severity_scores = {
            ThreatSeverity.LOW: 0.3,
            ThreatSeverity.MEDIUM: 0.6,
            ThreatSeverity.HIGH: 0.85,
            ThreatSeverity.CRITICAL: 0.95
        }
        
        for severity, expected_score in severity_scores.items():
            threat = ThreatEvent(
                severity=severity,
                threat_type=ThreatType.UNKNOWN,
                description="Test"
            )
            score = await ml_service.detect_anomaly(threat)
            assert score == expected_score
    
    @pytest.mark.asyncio
    async def test_detect_anomaly_with_model(self, ml_service):
        """Test anomaly detection with actual model"""
        mock_model = MagicMock()
        mock_model.predict.return_value = np.array([-1])  # Anomaly
        mock_model.decision_function.return_value = np.array([-0.3])
        
        ml_service.model = mock_model
        ml_service.initialized = True
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            source_pod="test-pod",
            falco_rule="Test rule",
            description="Test"
        )
        
        score = await ml_service.detect_anomaly(threat)
        
        assert 0.0 <= score <= 1.0
        mock_model.predict.assert_called_once()
        mock_model.decision_function.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_feature_extraction(self, ml_service):
        """Test feature extraction from threat event"""
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            source_user="root",
            falco_rule="Reverse shell detected",
            description="Test description"
        )
        
        features = ml_service._extract_features(threat)
        
        assert len(features) == 15  # Updated to 15 features
        assert all(isinstance(f, (int, float)) for f in features)
        assert features[1] == 1.0  # Has pod
        assert features[2] == 1.0  # Has user
    
    @pytest.mark.asyncio
    async def test_detect_anomaly_error_handling(self, ml_service):
        """Test error handling in anomaly detection"""
        mock_model = MagicMock()
        mock_model.predict.side_effect = Exception("Model error")
        
        ml_service.model = mock_model
        ml_service.initialized = True
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN,
            description="Test"
        )
        
        score = await ml_service.detect_anomaly(threat)
        
        # Should return default neutral score on error
        assert score == 0.5
    
    @pytest.mark.asyncio
    async def test_health_check(self, ml_service):
        """Test health check"""
        ml_service.initialized = True
        ml_service.model = MagicMock()
        
        health = await ml_service.health_check()
        
        assert health["status"] == "healthy"
        assert health["model_loaded"] is True
    
    @pytest.mark.asyncio
    async def test_health_check_degraded(self, ml_service):
        """Test health check when degraded"""
        ml_service.initialized = False
        ml_service.model = None
        
        health = await ml_service.health_check()
        
        assert health["status"] == "degraded"
        assert health["model_loaded"] is False
