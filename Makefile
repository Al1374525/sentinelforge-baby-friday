.PHONY: up demo attack clean build test install

# Build and start all services
up:
	@echo "🚀 Starting SentinelForge..."
	docker compose up -d
	@echo "✅ Services started. Backend: http://localhost:8000, Frontend: http://localhost:8501"

# Build services
build:
	@echo "🔨 Building Docker images..."
	docker compose build

# Start with Kubernetes cluster (for Falco testing)
up-k8s:
	@echo "🚀 Starting SentinelForge with Kubernetes..."
	kind create cluster --config kind-config.yaml --name sentinelforge || true
	kubectl apply -f https://raw.githubusercontent.com/falcosecurity/charts/master/falco/falco.yaml
	@echo "⏳ Waiting for Falco to be ready..."
	timeout /t 30 /nobreak >nul 2>&1 || sleep 30
	docker compose up -d backend frontend ollama
	@echo "✅ Services started. Backend: http://localhost:8000, Frontend: http://localhost:8501"

# Demo message
demo:
	@echo "🛡️ SentinelForge is protecting your systems!"
	@echo "   Backend API: http://localhost:8000"
	@echo "   Streamlit UI: http://localhost:8501"
	@echo "   Run 'make attack' to simulate a threat"

# Simulate attack
attack:
	@echo "🔥 Simulating attack..."
	kubectl apply -f attacker/evil-pod.yaml || echo "⚠️  Kubernetes not available, use API endpoint /api/v1/simulate"

# Install Python dependencies locally
install:
	@echo "📦 Installing Python dependencies..."
	pip install -r backend/requirements.txt
	pip install -r frontend/requirements.txt

# Run tests
test:
	@echo "🧪 Running tests..."
	pytest tests/ -v

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	docker compose down
	kind delete cluster --name sentinelforge 2>/dev/null || true
	@echo "✅ Cleanup complete"

# View logs
logs:
	docker compose logs -f

# Backend logs only
logs-backend:
	docker compose logs -f backend

# Frontend logs only
logs-frontend:
	docker compose logs -f frontend
