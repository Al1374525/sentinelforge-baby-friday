"""
Load tests for event ingestion
"""
import pytest
import time
from fastapi.testclient import TestClient
from tests.fixtures.falco_events import generate_high_volume_events


@pytest.mark.load
@pytest.mark.slow
class TestEventIngestion:
    """Load tests for event ingestion"""
    
    def test_high_volume_event_ingestion(self, test_client, reset_storage):
        """Test ingesting high volume of events"""
        events = generate_high_volume_events(100)
        
        start_time = time.time()
        
        # Send all events
        for event in events:
            response = test_client.post("/api/v1/falco/webhook", json=event)
            assert response.status_code == 200
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Verify all threats created
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        
        assert len(threats) >= 100
        assert duration < 30.0  # Should process 100 events in under 30 seconds
        
        # Calculate throughput
        throughput = len(events) / duration
        print(f"Processed {len(events)} events in {duration:.2f}s ({throughput:.2f} events/sec)")
    
    def test_concurrent_event_ingestion(self, test_client, reset_storage):
        """Test concurrent event ingestion"""
        import concurrent.futures
        events = generate_high_volume_events(50)
        
        def send_event(event):
            response = test_client.post("/api/v1/falco/webhook", json=event)
            return response.status_code == 200
        
        start_time = time.time()
        
        # Send events concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(send_event, events))
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Verify all succeeded
        assert all(results)
        
        # Verify threats created
        response = test_client.get("/api/v1/threats")
        threats = response.json()
        
        assert len(threats) >= 50
        print(f"Processed {len(events)} concurrent events in {duration:.2f}s")
    
    def test_api_endpoint_stress(self, test_client, reset_storage):
        """Test API endpoint stress"""
        # Create some threats first
        from tests.fixtures.falco_events import REVERSE_SHELL_EVENT
        for _ in range(10):
            test_client.post("/api/v1/falco/webhook", json=REVERSE_SHELL_EVENT)
        
        # Stress test threats endpoint
        start_time = time.time()
        requests = 100
        
        for _ in range(requests):
            response = test_client.get("/api/v1/threats")
            assert response.status_code == 200
        
        end_time = time.time()
        duration = end_time - start_time
        
        rps = requests / duration
        print(f"Handled {requests} requests in {duration:.2f}s ({rps:.2f} req/sec)")
        
        assert rps > 10  # Should handle at least 10 req/sec
