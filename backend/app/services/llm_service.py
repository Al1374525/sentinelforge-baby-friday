"""
LLM Service - Threat Explanation
Supports both cloud APIs (OpenAI/Anthropic) and Ollama
"""
import os
from typing import Optional
from app.models.threat_event import ThreatEvent
from app.utils.logging import get_logger

logger = get_logger(__name__)


class LLMService:
    """LLM service for generating threat explanations"""
    
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "openai")  # openai, anthropic, ollama
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.initialized = False
    
    async def initialize(self):
        """Initialize LLM service"""
        try:
            # Check if we have API keys or Ollama available
            if self.provider in ["openai", "anthropic"] and self.api_key:
                self.initialized = True
                logger.info(f"LLM Service initialized ({self.provider})")
            elif self.provider == "ollama":
                # Try to connect to Ollama
                import httpx
                async with httpx.AsyncClient() as client:
                    response = await client.get(f"{self.ollama_url}/api/tags", timeout=5.0)
                    if response.status_code == 200:
                        self.initialized = True
                        logger.info("LLM Service initialized (Ollama)")
                    else:
                        logger.warning("Ollama not available, LLM service in mock mode")
            else:
                logger.warning("No LLM provider configured, using template-based explanations")
        except Exception as e:
            logger.error(f"Error initializing LLM service: {e}", exc_info=True)
            self.initialized = False
    
    async def explain_threat(self, threat: ThreatEvent) -> str:
        """
        Generate FRIDAY-style explanation of threat
        Returns human-readable explanation
        """
        if not self.initialized:
            # Fallback to template-based explanation
            return self._template_explanation(threat)
        
        try:
            if self.provider == "openai":
                return await self._explain_openai(threat)
            elif self.provider == "anthropic":
                return await self._explain_anthropic(threat)
            elif self.provider == "ollama":
                return await self._explain_ollama(threat)
            else:
                return self._template_explanation(threat)
        except Exception as e:
            logger.error(f"Error generating LLM explanation: {e}", exc_info=True)
            return self._template_explanation(threat)
    
    async def _explain_openai(self, threat: ThreatEvent) -> str:
        """Generate explanation using OpenAI API"""
        try:
            import openai
            
            prompt = f"""You are FRIDAY, Tony Stark's AI assistant. Explain this security threat in a concise, professional manner:

Threat Type: {threat.threat_type.value}
Severity: {threat.severity.value}
Pod: {threat.source_pod}
Description: {threat.description[:200]}

Provide a brief explanation starting with "Sir," in FRIDAY's style."""
            
            client = openai.AsyncOpenAI(api_key=self.api_key)
            response = await client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=150
            )
            
            return response.choices[0].message.content.strip()
        except ImportError:
            return self._template_explanation(threat)
    
    async def _explain_anthropic(self, threat: ThreatEvent) -> str:
        """Generate explanation using Anthropic API"""
        try:
            import anthropic
            
            prompt = f"""You are FRIDAY, Tony Stark's AI assistant. Explain this security threat:

Threat Type: {threat.threat_type.value}
Severity: {threat.severity.value}
Pod: {threat.source_pod}
Description: {threat.description[:200]}

Provide a brief explanation starting with "Sir," in FRIDAY's style."""
            
            client = anthropic.AsyncAnthropic(api_key=self.api_key)
            response = await client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=150,
                messages=[{"role": "user", "content": prompt}]
            )
            
            return response.content[0].text.strip()
        except ImportError:
            return self._template_explanation(threat)
    
    async def _explain_ollama(self, threat: ThreatEvent) -> str:
        """Generate explanation using Ollama"""
        try:
            import httpx
            
            prompt = f"""You are FRIDAY, Tony Stark's AI assistant. Explain this security threat:

Threat Type: {threat.threat_type.value}
Severity: {threat.severity.value}
Pod: {threat.source_pod}
Description: {threat.description[:200]}

Provide a brief explanation starting with "Sir," in FRIDAY's style."""
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": "llama2",  # or whatever model is available
                        "prompt": prompt,
                        "stream": False
                    },
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json().get("response", "").strip()
                else:
                    return self._template_explanation(threat)
        except Exception:
            return self._template_explanation(threat)
    
    def _template_explanation(self, threat: ThreatEvent) -> str:
        """Fallback template-based explanation"""
        pod_name = threat.source_pod or "unknown pod"
        threat_desc = threat.threat_type.value.replace("_", " ").title()
        
        if threat.severity.value == "critical":
            return f"Sir, I've detected a critical {threat_desc} threat in pod {pod_name}. Immediate action is required to secure the system."
        elif threat.severity.value == "high":
            return f"Sir, a high-severity {threat_desc} threat has been detected in pod {pod_name}. I recommend reviewing this immediately."
        else:
            return f"Sir, I've detected a {threat_desc} event in pod {pod_name}. Monitoring for escalation."
    
    async def health_check(self) -> dict:
        """Health check for LLM service"""
        return {
            "status": "healthy" if self.initialized else "degraded",
            "provider": self.provider
        }
