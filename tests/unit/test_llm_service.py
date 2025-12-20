"""
Unit tests for LLMService
"""
import pytest
import os
from unittest.mock import patch, AsyncMock, MagicMock
from app.services.llm_service import LLMService
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType


@pytest.mark.unit
@pytest.mark.asyncio
class TestLLMService:
    """Test LLMService"""
    
    @pytest.fixture
    def llm_service(self):
        """Create LLMService instance"""
        return LLMService()
    
    @pytest.mark.asyncio
    async def test_initialize_openai(self, llm_service):
        """Test initialization with OpenAI"""
        with patch.dict(os.environ, {"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "test-key"}):
            service = LLMService()
            await service.initialize()
            
            assert service.initialized is True
            assert service.provider == "openai"
    
    @pytest.mark.asyncio
    async def test_initialize_anthropic(self, llm_service):
        """Test initialization with Anthropic"""
        with patch.dict(os.environ, {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test-key"}):
            service = LLMService()
            await service.initialize()
            
            assert service.initialized is True
            assert service.provider == "anthropic"
    
    @pytest.mark.asyncio
    async def test_initialize_ollama(self, llm_service):
        """Test initialization with Ollama"""
        with patch.dict(os.environ, {"LLM_PROVIDER": "ollama"}):
            service = LLMService()
            
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_client.return_value.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
                
                await service.initialize()
                
                assert service.initialized is True
                assert service.provider == "ollama"
    
    @pytest.mark.asyncio
    async def test_initialize_no_provider(self, llm_service):
        """Test initialization without provider"""
        with patch.dict(os.environ, {}, clear=True):
            service = LLMService()
            await service.initialize()
            
            # Should still initialize but in mock mode
            assert service.provider == "openai"  # Default
    
    @pytest.mark.asyncio
    async def test_template_explanation_critical(self, llm_service):
        """Test template-based explanation for critical threat"""
        llm_service.initialized = False
        
        threat = ThreatEvent(
            severity=ThreatSeverity.CRITICAL,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="evil-pod",
            description="Reverse shell detected"
        )
        
        explanation = await llm_service.explain_threat(threat)
        
        assert "Sir" in explanation
        assert "critical" in explanation.lower()
        assert "evil-pod" in explanation
        assert "immediate action" in explanation.lower()
    
    @pytest.mark.asyncio
    async def test_template_explanation_high(self, llm_service):
        """Test template-based explanation for high severity threat"""
        llm_service.initialized = False
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.PRIVILEGE_ESCALATION,
            source_pod="suspicious-pod"
        )
        
        explanation = await llm_service.explain_threat(threat)
        
        assert "Sir" in explanation
        assert "high" in explanation.lower()
        assert "suspicious-pod" in explanation
    
    @pytest.mark.asyncio
    async def test_template_explanation_medium(self, llm_service):
        """Test template-based explanation for medium severity threat"""
        llm_service.initialized = False
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            source_pod="network-pod"
        )
        
        explanation = await llm_service.explain_threat(threat)
        
        assert "Sir" in explanation
        assert "network-pod" in explanation
    
    @pytest.mark.asyncio
    async def test_explain_openai(self, llm_service, mock_openai_client):
        """Test OpenAI explanation generation"""
        llm_service.initialized = True
        llm_service.provider = "openai"
        llm_service.api_key = "test-key"
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            description="Test threat"
        )
        
        with patch('app.services.llm_service.openai.AsyncOpenAI', return_value=mock_openai_client):
            explanation = await llm_service.explain_threat(threat)
            
            assert "Sir" in explanation
            mock_openai_client.chat.completions.create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_explain_anthropic(self, llm_service, mock_anthropic_client):
        """Test Anthropic explanation generation"""
        llm_service.initialized = True
        llm_service.provider = "anthropic"
        llm_service.api_key = "test-key"
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            description="Test threat"
        )
        
        with patch('app.services.llm_service.anthropic.AsyncAnthropic', return_value=mock_anthropic_client):
            explanation = await llm_service.explain_threat(threat)
            
            assert "Sir" in explanation
            mock_anthropic_client.messages.create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_explain_ollama(self, llm_service, mock_ollama_response):
        """Test Ollama explanation generation"""
        llm_service.initialized = True
        llm_service.provider = "ollama"
        llm_service.ollama_url = "http://localhost:11434"
        
        threat = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            source_pod="test-pod",
            description="Test threat"
        )
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_ollama_response
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(return_value=mock_response)
            
            explanation = await llm_service.explain_threat(threat)
            
            assert "Sir" in explanation
    
    @pytest.mark.asyncio
    async def test_explain_error_fallback(self, llm_service):
        """Test that errors fall back to template"""
        llm_service.initialized = True
        llm_service.provider = "openai"
        
        threat = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            source_pod="test-pod"
        )
        
        with patch('app.services.llm_service.openai.AsyncOpenAI', side_effect=Exception("API error")):
            explanation = await llm_service.explain_threat(threat)
            
            # Should fall back to template
            assert "Sir" in explanation
            assert "test-pod" in explanation
    
    @pytest.mark.asyncio
    async def test_health_check(self, llm_service):
        """Test health check"""
        llm_service.initialized = True
        llm_service.provider = "openai"
        
        health = await llm_service.health_check()
        
        assert health["status"] == "healthy"
        assert health["provider"] == "openai"
    
    @pytest.mark.asyncio
    async def test_health_check_degraded(self, llm_service):
        """Test health check when degraded"""
        llm_service.initialized = False
        llm_service.provider = "openai"
        
        health = await llm_service.health_check()
        
        assert health["status"] == "degraded"
        assert health["provider"] == "openai"
