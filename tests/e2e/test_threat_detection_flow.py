"""
End-to-end tests for threat detection flow
"""
import pytest
from fastapi.testclient import TestClient
from tests.fixtures.falco_events import REVERSE_SHELL_EVENT


@pytest.mark.e2e
@pytest.mark.slow
class TestThreatDetectionFlow:
    """End-to-end tests for threat detection"""
    
    def test_complete_threat_detection_flow(self, test_client, reset_storage):
        """Test complete flow from threat detection to frontend display"""
        # Step 1: Simulate Falco detecting threat and sending webhook
        response = test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        assert response.status_code == 200
        
        webhook_response = response.json()
        assert webhook_response["status"] == "processed"
        
        # Step 2: Verify threat appears in threats endpoint
        response = test_client.get("/api/v1/threats")
        assert response.status_code == 200
        
        threats = response.json()
        assert len(threats) > 0
        
        threat = threats[0]
        assert threat["severity"] in ["high", "critical"]
        assert threat["threat_type"] == "reverse_shell"
        assert threat["source_pod"] == "evil-pod"
        
        # Step 3: Verify threat details endpoint
        threat_id = threat["id"]
        response = test_client.get(f"/api/v1/threats/{threat_id}")
        assert response.status_code == 200
        
        threat_details = response.json()
        assert threat_details["id"] == threat_id
        assert threat_details["falco_rule"] == "Reverse shell detected"
        
        # Step 4: Verify action was generated
        response = test_client.get("/api/v1/actions")
        assert response.status_code == 200
        
        actions = response.json()
        # Action may or may not be created depending on confidence/risk level
        # But if created, should be linked to threat
        if len(actions) > 0:
            action = actions[0]
            assert action["threat_id"] == threat_id
            assert action["action_type"] in ["terminate_pod", "isolate_pod", "alert"]
        
        # Step 5: Verify explanation can be generated
        response = test_client.get(f"/api/v1/explain/{threat_id}")
        assert response.status_code == 200
        
        explanation = response.json()
        assert "explanation" in explanation
        assert explanation["threat_id"] == threat_id
    
    def test_threat_filtering(self, test_client, reset_storage):
        """Test threat filtering capabilities"""
        # Create multiple threats with different severities
        from tests.fixtures.falco_events import (
            REVERSE_SHELL_EVENT,
            NETWORK_ANOMALY_EVENT,
            LOW_SEVERITY_EVENT
        )
        
        test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        test_client.post("/api/v1/falco/webhook", json=NETWORK_ANOMALY_EVENT)
        test_client.post("/api/v1/falco/webhook", json=LOW_SEVERITY_EVENT)
        
        # Filter by high severity
        response = test_client.get("/api/v1/threats?severity=high")
        high_threats = response.json()
        assert all(t["severity"] == "high" for t in high_threats)
        
        # Filter by threat type
        response = test_client.get("/api/v1/threats?threat_type=reverse_shell")
        reverse_shell_threats = response.json()
        assert all(t["threat_type"] == "reverse_shell" for t in reverse_shell_threats)
    
    def test_simulate_endpoint(self, test_client, reset_storage):
        """Test simulate endpoint for testing"""
        event = {
            "output": "17:20:42.123456789: Warning Test simulation",
            "priority": "Warning",
            "rule": "Test rule",
            "output_fields": {
                "k8s.pod.name": "simulated-pod",
                "k8s.ns.name": "test"
            }
        }
        
        response = test_client.post("/api/v1/simulate", json=event)
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        
        # Verify threat was created
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        assert len(threats) > 0
