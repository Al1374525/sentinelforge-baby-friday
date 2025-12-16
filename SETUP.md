# SentinelForge Setup Guide

## Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- Kubernetes cluster (Kind/minikube) for Falco testing
- (Optional) OpenAI or Anthropic API key for LLM explanations

## Quick Start

### 1. Clone and Setup

```bash
cd sentinelforge-baby-friday
cp .env.example .env
# Edit .env with your API keys if using cloud LLM
```

### 2. Start Services

```bash
# Simple start (no Kubernetes)
make up

# Or with Kubernetes cluster (for Falco)
make up-k8s
```

### 3. Access Services

- **Backend API**: http://localhost:8000
- **Streamlit UI**: http://localhost:8501
- **API Docs**: http://localhost:8000/docs

### 4. Test Threat Detection

```bash
# Simulate attack (requires Kubernetes)
make attack

# Or send test event via API
curl -X POST http://localhost:8000/api/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "output": "17:20:42.123456789: Warning Terminal shell in container",
    "priority": "Warning",
    "rule": "Terminal shell in container",
    "output_fields": {
      "k8s.pod.name": "test-pod",
      "k8s.ns.name": "default"
    }
  }'
```

## Development Setup

### Local Python Development

```bash
# Install dependencies
make install

# Run backend locally
cd backend
uvicorn app.main:app --reload

# Run frontend locally (in another terminal)
cd frontend
streamlit run streamlit_app.py
```

### Environment Variables

Set these in `.env` or export them:

- `LLM_PROVIDER`: `openai`, `anthropic`, or `ollama`
- `OPENAI_API_KEY`: Your OpenAI API key
- `ANTHROPIC_API_KEY`: Your Anthropic API key
- `OLLAMA_URL`: Ollama server URL (default: http://localhost:11434)

## Architecture Decisions

Based on your choices:
- ✅ Streamlit UI for MVP (React 3D UI in Phase 2)
- ✅ Cloud LLM APIs (OpenAI/Anthropic) with Ollama fallback
- ✅ Moderate RL agent (confidence-based actions)
- ✅ AWS-focused (for Phase 3)
- ✅ Both local and K8s Falco support

## Project Structure

```
sentinelforge-baby-friday/
├── backend/          # FastAPI backend
├── frontend/         # Streamlit UI
├── ml/              # ML models (to be implemented)
├── rl/              # RL agent (to be implemented)
├── falco/           # Falco rules
├── k8s/             # Kubernetes manifests
├── docker/          # Dockerfiles
└── tests/           # Test suite
```

## Next Steps

1. ✅ Project structure created
2. ⏭️ Enhanced Falco integration (custom rules)
3. ⏭️ ML anomaly detection
4. ⏭️ RL agent training
5. ⏭️ Database integration (Phase 2)

## Troubleshooting

### Backend won't start
- Check Docker is running
- Check port 8000 is not in use
- View logs: `make logs-backend`

### Frontend won't connect to backend
- Ensure backend is running
- Check API_BASE_URL in frontend environment
- View logs: `make logs-frontend`

### Falco not detecting threats
- Ensure Falco is running in Kubernetes: `kubectl get pods -n falco`
- Check Falco logs: `kubectl logs -n falco -l app=falco`
- Verify custom rules are loaded

### LLM explanations not working
- Check API keys in `.env`
- Verify LLM_PROVIDER is set correctly
- Check service logs for errors

## Testing

```bash
# Run all tests
make test

# Test API endpoints
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/threats
```

## Cleanup

```bash
# Stop all services
make clean
```
