"""
Integration tests for frontend-backend communication
"""
import pytest
from fastapi.testclient import TestClient
from tests.fixtures.falco_events import REVERSE_SHELL_EVENT


@pytest.mark.integration
class TestFrontendBackend:
    """Test frontend-backend integration"""
    
    def test_frontend_can_fetch_threats(self, test_client, reset_storage):
        """Test that frontend can fetch threats from API"""
        # Create threats via webhook
        test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        # Simulate frontend request
        response = test_client.get("/api/v1/threats?limit=50")
        
        assert response.status_code == 200
        threats = response.json()
        assert isinstance(threats, list)
        
        if len(threats) > 0:
            threat = threats[0]
            # Verify threat has required fields for frontend
            assert "id" in threat
            assert "severity" in threat
            assert "threat_type" in threat
            assert "detected_at" in threat
            assert "description" in threat
    
    def test_frontend_can_fetch_actions(self, test_client, reset_storage):
        """Test that frontend can fetch actions from API"""
        # Create threat that generates action
        test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        # Simulate frontend request
        response = test_client.get("/api/v1/actions?limit=50")
        
        assert response.status_code == 200
        actions = response.json()
        assert isinstance(actions, list)
    
    def test_frontend_health_check(self, test_client):
        """Test that frontend can check backend health"""
        response = test_client.get("/health")
        
        assert response.status_code == 200
        health = response.json()
        
        assert health["status"] == "healthy"
        assert "services" in health
        
        # Verify all services are reported
        services = health["services"]
        assert "ml" in services
        assert "rl" in services
        assert "llm" in services
        assert "remediation" in services
    
    def test_frontend_explanation_request(self, test_client, reset_storage):
        """Test that frontend can request threat explanations"""
        # Create threat
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        # Get threat ID
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        
        if len(threats) > 0:
            threat_id = threats[0]["id"]
            
            # Request explanation (simulating frontend button click)
            response = test_client.get(f"/api/v1/explain/{threat_id}")
            
            assert response.status_code == 200
            explanation = response.json()
            assert "explanation" in explanation
            assert "summary" in explanation
