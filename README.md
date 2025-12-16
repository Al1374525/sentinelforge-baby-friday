# SentinelForge - Autonomous Cybersecurity Platform

**Status**: Phase 1 - Enhanced Prototype Development  
**Vision**: FRIDAY-inspired autonomous cybersecurity system

## Project Structure

```
sentinelforge-baby-friday/
├── backend/                    # FastAPI backend (renamed from 'brain')
│   ├── app/
│   │   ├── api/               # API endpoints
│   │   ├── services/          # Business logic
│   │   ├── models/            # Data models
│   │   └── main.py            # FastAPI app entry
│   ├── database/              # Database models & migrations
│   └── requirements.txt
├── frontend/                   # Streamlit UI (MVP)
│   └── streamlit_app.py
├── ml/                         # Machine Learning models
│   ├── feature_extractor.py
│   ├── anomaly_detector.py
│   └── train.py
├── rl/                         # Reinforcement Learning
│   ├── cyber_env.py
│   ├── agent.py
│   └── train_agent.py
├── falco/                      # Falco configuration
│   └── rules/
├── k8s/                        # Kubernetes manifests
├── docker/                     # Dockerfiles
├── tests/                      # Test suite
├── attacker/                   # Test attack scenarios
├── docker-compose.yml
└── Makefile
```

## Quick Start

```bash
# Start services
make up

# Run attack simulation
make attack

# View logs
docker compose logs -f brain
```

## Architecture Decisions

See `SENTINELFORGE_DECISIONS.md` for key decisions.

## Development Status

- ✅ Basic FastAPI backend
- ✅ Simple Falco integration
- ✅ Kubernetes pod termination
- ⏭️ Enhanced Falco rules
- ⏭️ ML anomaly detection
- ⏭️ RL agent
- ⏭️ Streamlit UI
- ⏭️ LLM threat explanations
