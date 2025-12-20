"""
Unit tests for threats API endpoints
"""
import pytest
from fastapi.testclient import TestClient
from app.models.threat_event import ThreatSeverity, ThreatType


@pytest.mark.unit
class TestThreatsAPI:
    """Test threats API endpoints"""
    
    def test_list_threats_empty(self, test_client, reset_storage):
        """Test listing threats when none exist"""
        response = test_client.get("/api/v1/threats")
        
        assert response.status_code == 200
        assert response.json() == []
    
    def test_list_threats(self, test_client, reset_storage, sample_threat_event):
        """Test listing threats"""
        response = test_client.get("/api/v1/threats")
        
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 1
        assert threats[0]["id"] == str(sample_threat_event.id)
    
    def test_list_threats_filter_by_severity(self, test_client, reset_storage):
        """Test filtering threats by severity"""
        from app.storage import threats_db
        from app.models.threat_event import ThreatEvent
        
        # Create threats with different severities
        threat_high = ThreatEvent(
            severity=ThreatSeverity.HIGH,
            threat_type=ThreatType.REVERSE_SHELL,
            description="High threat"
        )
        threat_low = ThreatEvent(
            severity=ThreatSeverity.LOW,
            threat_type=ThreatType.UNKNOWN,
            description="Low threat"
        )
        threats_db.extend([threat_high, threat_low])
        
        # Filter by high severity
        response = test_client.get("/api/v1/threats?severity=high")
        
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 1
        assert threats[0]["severity"] == "high"
    
    def test_list_threats_filter_by_type(self, test_client, reset_storage):
        """Test filtering threats by type"""
        from app.storage import threats_db
        from app.models.threat_event import ThreatEvent
        
        threat1 = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.REVERSE_SHELL,
            description="Reverse shell"
        )
        threat2 = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.NETWORK_ANOMALY,
            description="Network anomaly"
        )
        threats_db.extend([threat1, threat2])
        
        response = test_client.get("/api/v1/threats?threat_type=reverse_shell")
        
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 1
        assert threats[0]["threat_type"] == "reverse_shell"
    
    def test_list_threats_filter_by_resolved(self, test_client, reset_storage):
        """Test filtering threats by resolved status"""
        from app.storage import threats_db
        from app.models.threat_event import ThreatEvent
        from datetime import datetime
        
        threat_resolved = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN,
            description="Resolved threat",
            resolved=True,
            resolved_at=datetime.utcnow()
        )
        threat_unresolved = ThreatEvent(
            severity=ThreatSeverity.MEDIUM,
            threat_type=ThreatType.UNKNOWN,
            description="Unresolved threat",
            resolved=False
        )
        threats_db.extend([threat_resolved, threat_unresolved])
        
        # Filter resolved
        response = test_client.get("/api/v1/threats?resolved=true")
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 1
        assert threats[0]["resolved"] is True
        
        # Filter unresolved
        response = test_client.get("/api/v1/threats?resolved=false")
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 1
        assert threats[0]["resolved"] is False
    
    def test_list_threats_limit(self, test_client, reset_storage):
        """Test limiting number of threats returned"""
        from app.storage import threats_db
        from app.models.threat_event import ThreatEvent
        
        # Create 5 threats
        for i in range(5):
            threat = ThreatEvent(
                severity=ThreatSeverity.MEDIUM,
                threat_type=ThreatType.UNKNOWN,
                description=f"Threat {i}"
            )
            threats_db.append(threat)
        
        # Limit to 2
        response = test_client.get("/api/v1/threats?limit=2")
        
        assert response.status_code == 200
        threats = response.json()
        assert len(threats) == 2
    
    def test_get_threat_by_id(self, test_client, reset_storage, sample_threat_event):
        """Test getting threat by ID"""
        threat_id = str(sample_threat_event.id)
        response = test_client.get(f"/api/v1/threats/{threat_id}")
        
        assert response.status_code == 200
        threat = response.json()
        assert threat["id"] == threat_id
        assert threat["severity"] == "high"
        assert threat["threat_type"] == "reverse_shell"
    
    def test_get_threat_not_found(self, test_client, reset_storage):
        """Test getting non-existent threat"""
        from uuid import uuid4
        
        threat_id = str(uuid4())
        response = test_client.get(f"/api/v1/threats/{threat_id}")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_resolve_threat(self, test_client, reset_storage, sample_threat_event):
        """Test resolving a threat"""
        threat_id = str(sample_threat_event.id)
        response = test_client.post(f"/api/v1/threats/{threat_id}/resolve")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "resolved"
        assert data["threat_id"] == threat_id
        
        # Verify threat is marked as resolved
        from app.storage import threats_db
        threat = next(t for t in threats_db if t.id == sample_threat_event.id)
        assert threat.resolved is True
        assert threat.resolved_at is not None
    
    def test_resolve_threat_not_found(self, test_client, reset_storage):
        """Test resolving non-existent threat"""
        from uuid import uuid4
        
        threat_id = str(uuid4())
        response = test_client.post(f"/api/v1/threats/{threat_id}/resolve")
        
        assert response.status_code == 404
