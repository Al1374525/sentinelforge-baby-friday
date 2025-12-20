"""
Unit tests for FalcoProcessor service
"""
import pytest
from unittest.mock import AsyncMock, patch
from app.services.falco_processor import FalcoProcessor
from app.models.threat_event import ThreatSeverity, ThreatType
from tests.fixtures.falco_events import (
    REVERSE_SHELL_EVENT,
    PRIVILEGE_ESCALATION_EVENT,
    NETWORK_ANOMALY_EVENT,
    CONTAINER_ESCAPE_EVENT,
    LOW_SEVERITY_EVENT,
    MALFORMED_EVENT,
    INCOMPLETE_EVENT
)


@pytest.mark.unit
@pytest.mark.asyncio
class TestFalcoProcessor:
    """Test FalcoProcessor service"""
    
    @pytest.fixture
    def processor(self):
        """Create FalcoProcessor instance"""
        return FalcoProcessor()
    
    @pytest.mark.asyncio
    async def test_process_reverse_shell_event(self, processor, reset_storage):
        """Test processing reverse shell event"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(REVERSE_SHELL_EVENT)
            
            assert threat is not None
            assert threat.severity == ThreatSeverity.HIGH  # Critical maps to HIGH
            assert threat.threat_type == ThreatType.REVERSE_SHELL
            assert threat.source_pod == "evil-pod"
            assert threat.source_namespace == "default"
            assert threat.falco_rule == "Reverse shell detected"
            assert threat.falco_priority == "Critical"
    
    @pytest.mark.asyncio
    async def test_process_privilege_escalation_event(self, processor, reset_storage):
        """Test processing privilege escalation event"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(PRIVILEGE_ESCALATION_EVENT)
            
            assert threat is not None
            assert threat.severity == ThreatSeverity.HIGH  # Alert maps to HIGH
            assert threat.threat_type == ThreatType.PRIVILEGE_ESCALATION
            assert threat.source_pod == "suspicious-pod"
    
    @pytest.mark.asyncio
    async def test_process_network_anomaly_event(self, processor, reset_storage):
        """Test processing network anomaly event"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(NETWORK_ANOMALY_EVENT)
            
            assert threat is not None
            assert threat.severity == ThreatSeverity.MEDIUM  # Warning maps to MEDIUM
            assert threat.threat_type == ThreatType.NETWORK_ANOMALY
    
    @pytest.mark.asyncio
    async def test_process_container_escape_event(self, processor, reset_storage):
        """Test processing container escape event"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(CONTAINER_ESCAPE_EVENT)
            
            assert threat is not None
            assert threat.severity == ThreatSeverity.HIGH
            assert threat.threat_type == ThreatType.CONTAINER_ESCAPE
    
    @pytest.mark.asyncio
    async def test_process_low_severity_event(self, processor, reset_storage):
        """Test processing low severity event"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(LOW_SEVERITY_EVENT)
            
            assert threat is not None
            assert threat.severity == ThreatSeverity.LOW  # Notice maps to LOW
    
    @pytest.mark.asyncio
    async def test_severity_mapping(self, processor, reset_storage):
        """Test severity mapping for all priority levels"""
        priority_map = {
            "Emergency": ThreatSeverity.CRITICAL,
            "Alert": ThreatSeverity.HIGH,
            "Critical": ThreatSeverity.HIGH,
            "Error": ThreatSeverity.MEDIUM,
            "Warning": ThreatSeverity.MEDIUM,
            "Notice": ThreatSeverity.LOW,
            "Informational": ThreatSeverity.LOW,
            "Debug": ThreatSeverity.LOW
        }
        
        for priority, expected_severity in priority_map.items():
            event = {
                "output": f"Test {priority} event",
                "priority": priority,
                "rule": "Test rule",
                "output_fields": {"k8s.pod.name": "test-pod"}
            }
            
            with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
                threat = await processor.process_event(event)
                assert threat.severity == expected_severity, f"Failed for priority: {priority}"
    
    @pytest.mark.asyncio
    async def test_threat_type_detection(self, processor, reset_storage):
        """Test threat type detection from keywords"""
        test_cases = [
            ("nc -e /bin/sh", ThreatType.REVERSE_SHELL),
            ("bash -i", ThreatType.REVERSE_SHELL),
            ("sudo su", ThreatType.PRIVILEGE_ESCALATION),
            ("setuid", ThreatType.PRIVILEGE_ESCALATION),
            ("port scan", ThreatType.NETWORK_ANOMALY),
            ("/etc/passwd", ThreatType.FILE_ANOMALY),
            ("container escape", ThreatType.CONTAINER_ESCAPE),
        ]
        
        for keyword, expected_type in test_cases:
            event = {
                "output": f"Test event with {keyword}",
                "priority": "Warning",
                "rule": f"Rule with {keyword}",
                "output_fields": {"k8s.pod.name": "test-pod"}
            }
            
            with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
                threat = await processor.process_event(event)
                assert threat.threat_type == expected_type, f"Failed for keyword: {keyword}"
    
    @pytest.mark.asyncio
    async def test_malformed_event(self, processor, reset_storage):
        """Test handling of malformed events"""
        threat = await processor.process_event(MALFORMED_EVENT)
        # Should handle gracefully and return None or a threat with defaults
        # Current implementation may raise exception, which is acceptable
        assert threat is None or isinstance(threat, type(None))
    
    @pytest.mark.asyncio
    async def test_incomplete_event(self, processor, reset_storage):
        """Test handling of events with missing output_fields"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(INCOMPLETE_EVENT)
            
            assert threat is not None
            assert threat.source_pod is None or threat.source_pod == ""
            assert threat.source_namespace == "default"  # Default namespace
    
    @pytest.mark.asyncio
    async def test_websocket_broadcast(self, processor, reset_storage):
        """Test that WebSocket broadcast is called"""
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock) as mock_broadcast:
            threat = await processor.process_event(REVERSE_SHELL_EVENT)
            
            assert threat is not None
            mock_broadcast.assert_called_once()
            call_args = mock_broadcast.call_args[0][0]
            assert call_args["type"] == "threat_detected"
            assert call_args["threat_id"] == str(threat.id)
    
    @pytest.mark.asyncio
    async def test_threat_storage(self, processor, reset_storage):
        """Test that threats are stored in database"""
        from app.storage import threats_db
        
        initial_count = len(threats_db)
        
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(REVERSE_SHELL_EVENT)
            
            assert len(threats_db) == initial_count + 1
            assert threat in threats_db
    
    @pytest.mark.asyncio
    async def test_description_truncation(self, processor, reset_storage):
        """Test that long descriptions are truncated"""
        long_output = "x" * 1000
        event = {
            "output": long_output,
            "priority": "Warning",
            "rule": "Test rule",
            "output_fields": {"k8s.pod.name": "test-pod"}
        }
        
        with patch('app.services.falco_processor.manager.broadcast', new_callable=AsyncMock):
            threat = await processor.process_event(event)
            
            assert len(threat.description) <= 500  # Should be truncated
