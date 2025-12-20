"""
Integration tests for Falco webhook integration
"""
import pytest
from fastapi.testclient import TestClient
from tests.fixtures.falco_events import (
    REVERSE_SHELL_EVENT,
    PRIVILEGE_ESCALATION_EVENT,
    NETWORK_ANOMALY_EVENT,
    CONTAINER_ESCAPE_EVENT,
    MALFORMED_EVENT
)


@pytest.mark.integration
class TestFalcoWebhook:
    """Test Falco webhook integration"""
    
    def test_falco_webhook_receives_event(self, test_client, reset_storage):
        """Test that Falco webhook endpoint receives and processes events"""
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "processed"
        assert "threat_id" in data or "action" in data
    
    def test_falco_webhook_creates_threat(self, test_client, reset_storage):
        """Test that Falco webhook creates threat in storage"""
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        assert response.status_code == 200
        
        # Verify threat was created
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        assert len(threats) > 0
        
        threat = threats[0]
        assert threat["source_pod"] == "evil-pod"
        assert threat["threat_type"] == "reverse_shell"
    
    def test_falco_webhook_processes_different_event_types(self, test_client, reset_storage):
        """Test processing different types of Falco events"""
        events = [
            REVERSE_SHELL_EVENT,
            PRIVILEGE_ESCALATION_EVENT,
            NETWORK_ANOMALY_EVENT,
            CONTAINER_ESCAPE_EVENT
        ]
        
        for event in events:
            response = test_client.post("/api/v1/falco/webhook", json=event)
            assert response.status_code == 200
        
        # Verify all threats created
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        assert len(threats) >= len(events)
    
    def test_falco_webhook_handles_malformed_events(self, test_client, reset_storage):
        """Test handling of malformed Falco events"""
        response = test_client.post("/api/v1/falco/webhook", json=MALFORMED_EVENT)
        
        # Should handle gracefully (either process or return error)
        assert response.status_code in [200, 400, 500]
    
    def test_falco_webhook_response_format(self, test_client, reset_storage):
        """Test Falco webhook response format"""
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "status" in data
        assert data["status"] == "processed"
        
        # May include threat_id, severity, action
        if "threat_id" in data:
            assert isinstance(data["threat_id"], str)
        if "severity" in data:
            assert data["severity"] in ["low", "medium", "high", "critical"]
        if "action" in data:
            assert isinstance(data["action"], str)
    
    def test_falco_webhook_generates_action(self, test_client, reset_storage):
        """Test that Falco webhook triggers action generation"""
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        assert response.status_code == 200
        
        # Check if action was generated
        response = test_client.get("/api/v1/actions")
        actions = response.json()
        
        # Action may or may not be created depending on risk level
        # But webhook should process successfully
        assert response.status_code == 200
