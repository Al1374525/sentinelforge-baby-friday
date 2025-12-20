"""
Unit tests for explain API endpoints
"""
import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
class TestExplainAPI:
    """Test explain API endpoints"""
    
    def test_explain_threat(self, test_client, reset_storage, sample_threat_event):
        """Test explaining a threat"""
        threat_id = str(sample_threat_event.id)
        response = test_client.get(f"/api/v1/explain/{threat_id}")
        
        assert response.status_code == 200
        explanation = response.json()
        assert explanation["threat_id"] == threat_id
        assert "explanation" in explanation
        assert "summary" in explanation
        assert "details" in explanation
        assert explanation["severity"] == "high"
    
    def test_explain_threat_not_found(self, test_client, reset_storage):
        """Test explaining non-existent threat"""
        from uuid import uuid4
        
        threat_id = str(uuid4())
        response = test_client.get(f"/api/v1/explain/{threat_id}")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
