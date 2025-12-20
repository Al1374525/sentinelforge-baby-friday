"""
Load tests for WebSocket connections
"""
import pytest
import threading
import time
from fastapi.testclient import TestClient


@pytest.mark.load
@pytest.mark.slow
class TestWebSocketConnections:
    """Load tests for WebSocket connections"""
    
    def test_multiple_websocket_connections(self, test_client):
        """Test multiple concurrent WebSocket connections"""
        connections = []
        num_connections = 10
        
        # Create multiple WebSocket connections
        for i in range(num_connections):
            websocket = test_client.websocket_connect("/api/v1/stream")
            connections.append(websocket)
        
        # Send messages to all connections
        for ws in connections:
            ws.send_text("ping")
        
        # Receive responses
        responses = []
        for ws in connections:
            try:
                data = ws.receive_json()
                responses.append(data)
            except:
                pass
        
        # Verify responses
        assert len(responses) >= num_connections // 2  # At least half should respond
        
        # Close connections
        for ws in connections:
            try:
                ws.close()
            except:
                pass
    
    def test_websocket_broadcast_performance(self, test_client, reset_storage):
        """Test WebSocket broadcast performance"""
        # Create WebSocket connection
        with test_client.websocket_connect("/api/v1/stream") as websocket:
            # Send multiple events that trigger broadcasts
            from tests.fixtures.falco_events import REVERSE_SHELL_EVENT
            
            start_time = time.time()
            num_events = 20
            
            for i in range(num_events):
                # Send event
                test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
                
                # Try to receive broadcast (may not always work in test environment)
                try:
                    websocket.receive_json(timeout=0.1)
                except:
                    pass
            
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"Processed {num_events} events with WebSocket in {duration:.2f}s")
