"""
Unit tests for main API endpoints
"""
import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
class TestMainAPI:
    """Test main API endpoints"""
    
    def test_root_endpoint(self, test_client):
        """Test root health check endpoint"""
        response = test_client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "SentinelForge is online"
        assert data["status"] == "operational"
        assert "version" in data
    
    def test_health_endpoint(self, test_client):
        """Test detailed health check endpoint"""
        response = test_client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "services" in data
        assert "ml" in data["services"]
        assert "rl" in data["services"]
        assert "llm" in data["services"]
        assert "remediation" in data["services"]
    
    def test_simulate_endpoint(self, test_client, reset_storage):
        """Test simulate endpoint"""
        event = {
            "output": "17:20:42.123456789: Warning Test event",
            "priority": "Warning",
            "rule": "Test rule",
            "output_fields": {
                "k8s.pod.name": "test-pod",
                "k8s.ns.name": "default"
            }
        }
        
        response = test_client.post("/api/v1/simulate", json=event)
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "processed"
    
    def test_falco_webhook_endpoint(self, test_client, reset_storage):
        """Test Falco webhook endpoint"""
        event = {
            "output": "17:20:42.123456789: Warning Terminal shell in container",
            "priority": "Warning",
            "rule": "Terminal shell in container",
            "time": "2024-01-01T17:20:42.123456789Z",
            "output_fields": {
                "k8s.pod.name": "test-pod",
                "k8s.ns.name": "default",
                "container.name": "test-container"
            }
        }
        
        response = test_client.post("/api/v1/falco/webhook", json=event)
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "processed"
