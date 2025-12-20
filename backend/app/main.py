"""
SentinelForge - FastAPI Backend
Main application entry point
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import os

from app.api import threats, actions, stream, explain
from app.services.falco_processor import FalcoProcessor
from app.services.rl_service import RLService
from app.services.ml_service import MLService
from app.services.llm_service import LLMService
from app.services.remediation_service import RemediationService
from app.utils.logging import setup_logging, get_logger

# Setup logging
log_level = os.getenv("LOG_LEVEL", "INFO")
use_json_logs = os.getenv("JSON_LOGS", "false").lower() == "true"
setup_logging(level=log_level, use_json=use_json_logs)

logger = get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="SentinelForge",
    description="Autonomous Cybersecurity Platform - FRIDAY-inspired threat detection and response",
    version="0.1.0"
)

# CORS middleware for Streamlit/React frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
falco_processor = FalcoProcessor()
ml_service = MLService()
rl_service = RLService()
llm_service = LLMService()
remediation_service = RemediationService()

# Include routers
app.include_router(threats.router, prefix="/api/v1", tags=["threats"])
app.include_router(actions.router, prefix="/api/v1", tags=["actions"])
app.include_router(stream.router, prefix="/api/v1", tags=["stream"])
app.include_router(explain.router, prefix="/api/v1", tags=["explain"])


@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("SentinelForge backend starting...")
    await ml_service.initialize()
    await rl_service.initialize()
    await llm_service.initialize()
    logger.info("All services initialized")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("SentinelForge backend shutting down...")


@app.post("/api/v1/falco/webhook")
async def falco_webhook(request: Request):
    """
    Receive Falco events via webhook
    This is the main entry point for threat detection
    """
    try:
        event = await request.json()
        # Process Falco event through the pipeline
        threat = await falco_processor.process_event(event)
        
        if threat:
            # Run ML anomaly detection
            ml_score = await ml_service.detect_anomaly(threat)
            threat.ml_score = ml_score
            
            # Get RL agent decision
            action = await rl_service.decide_action(threat)
            
            # Execute remediation if confidence is high enough
            if action.confidence > 0.85 and action.risk_level == "low":
                await remediation_service.execute_action(action, threat)
            elif action.risk_level in ["medium", "high"]:
                # Log for human review
                logger.warning(
                    "Action requires confirmation",
                    extra={
                        "action_type": action.action_type.value,
                        "confidence": action.confidence,
                        "threat_id": str(threat.id)
                    }
                )
            
            logger.info(
                "Threat processed",
                extra={
                    "threat_id": str(threat.id),
                    "severity": threat.severity.value,
                    "threat_type": threat.threat_type.value,
                    "action": action.action_type.value if action else "monitor"
                }
            )
            
            return JSONResponse({
                "status": "processed",
                "threat_id": str(threat.id),
                "severity": threat.severity,
                "action": action.action_type if action else "monitor"
            })
        
        return JSONResponse({"status": "processed", "threat": None})
    
    except Exception as e:
        logger.error(
            "Error processing Falco event",
            extra={"error": str(e)},
            exc_info=True
        )
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/v1/simulate")
async def simulate(request: Request):
    """
    Simulate threat events for testing
    (Legacy endpoint from baby-friday)
    """
    try:
        event = await request.json()
        threat = await falco_processor.process_event(event)
        return JSONResponse({"status": "processed", "threat_id": str(threat.id) if threat else None})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "SentinelForge is online",
        "status": "operational",
        "version": "0.1.0"
    }


@app.get("/health")
async def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "services": {
            "ml": await ml_service.health_check(),
            "rl": await rl_service.health_check(),
            "llm": await llm_service.health_check(),
            "remediation": await remediation_service.health_check()
        }
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
