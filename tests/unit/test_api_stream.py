"""
Unit tests for WebSocket stream API
"""
import pytest
import json
from fastapi.testclient import TestClient


@pytest.mark.unit
class TestStreamAPI:
    """Test WebSocket stream API"""
    
    def test_websocket_connection(self, test_client):
        """Test WebSocket connection"""
        with test_client.websocket_connect("/api/v1/stream") as websocket:
            # Send a message
            websocket.send_text("ping")
            
            # Receive response
            data = websocket.receive_json()
            assert data["type"] == "ping"
            assert data["message"] == "connected"
    
    def test_websocket_multiple_connections(self, test_client):
        """Test multiple WebSocket connections"""
        with test_client.websocket_connect("/api/v1/stream") as ws1:
            with test_client.websocket_connect("/api/v1/stream") as ws2:
                # Both should connect successfully
                ws1.send_text("ping")
                ws2.send_text("ping")
                
                data1 = ws1.receive_json()
                data2 = ws2.receive_json()
                
                assert data1["type"] == "ping"
                assert data2["type"] == "ping"
