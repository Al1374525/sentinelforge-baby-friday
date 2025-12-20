"""
Integration tests for API endpoints
"""
import pytest
from fastapi.testclient import TestClient
from tests.fixtures.falco_events import REVERSE_SHELL_EVENT


@pytest.mark.integration
class TestAPIEndpoints:
    """Test API endpoint integration"""
    
    def test_falco_webhook_to_threats_endpoint(self, test_client, reset_storage):
        """Test that Falco webhook creates threat accessible via threats endpoint"""
        # Send Falco event via webhook
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        assert response.status_code == 200
        data = response.json()
        assert "threat_id" in data or "status" in data
        
        # Get threats
        response = test_client.get("/api/v1/threats")
        assert response.status_code == 200
        threats = response.json()
        
        # Should have at least one threat
        assert len(threats) > 0
        
        # Find the threat we just created
        threat = threats[0]
        assert threat["severity"] in ["high", "critical"]
        assert threat["threat_type"] == "reverse_shell"
    
    def test_threat_to_action_flow(self, test_client, reset_storage):
        """Test that threat processing creates action"""
        # Send Falco event
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        assert response.status_code == 200
        
        # Get threats
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        assert len(threats) > 0
        
        threat_id = threats[0]["id"]
        
        # Get actions (may be empty if action requires confirmation)
        response = test_client.get("/api/v1/actions")
        assert response.status_code == 200
        actions = response.json()
        
        # If action was created, verify it's linked to threat
        if len(actions) > 0:
            action = actions[0]
            assert action["threat_id"] == threat_id
    
    def test_explain_threat_flow(self, test_client, reset_storage):
        """Test threat explanation flow"""
        # Create threat via webhook
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        assert response.status_code == 200
        
        # Get threats
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        assert len(threats) > 0
        
        threat_id = threats[0]["id"]
        
        # Get explanation
        response = test_client.get(f"/api/v1/explain/{threat_id}")
        assert response.status_code == 200
        
        explanation = response.json()
        assert "explanation" in explanation
        assert explanation["threat_id"] == threat_id
    
    def test_resolve_threat_flow(self, test_client, reset_storage):
        """Test threat resolution flow"""
        # Create threat
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        assert response.status_code == 200
        
        # Get threats
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        assert len(threats) > 0
        
        threat_id = threats[0]["id"]
        assert threats[0]["resolved"] is False
        
        # Resolve threat
        response = test_client.post(f"/api/v1/threats/{threat_id}/resolve")
        assert response.status_code == 200
        
        # Verify resolved
        response = test_client.get(f"/api/v1/threats/{threat_id}")
        threat = response.json()
        assert threat["resolved"] is True
        
        # Filter resolved threats
        response = test_client.get("/api/v1/threats?resolved=true")
        resolved_threats = response.json()
        assert len(resolved_threats) > 0
        assert all(t["resolved"] for t in resolved_threats)
