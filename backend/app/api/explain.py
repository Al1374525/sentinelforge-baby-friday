"""
Threat Explanation API Endpoints
"""
from fastapi import APIRouter, HTTPException
from uuid import UUID
from app.models.threat_event import ThreatEvent

router = APIRouter()


@router.get("/explain/{threat_id}")
async def explain_threat(threat_id: str):
    """
    Get human-readable explanation of a threat
    Uses LLM to generate FRIDAY-style explanations
    """
    from app.storage import get_threats_db
    
    threat_id_uuid = UUID(threat_id)
    
    # Find threat
    threats_db = get_threats_db()
    threat = None
    for t in threats_db:
        if t.id == threat_id_uuid:
            threat = t
            break
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Generate explanation (will be implemented in LLM service)
    explanation = {
        "threat_id": str(threat.id),
        "summary": f"Detected {threat.threat_type.value} threat in pod {threat.source_pod}",
        "details": threat.description,
        "severity": threat.severity.value,
        "detected_at": threat.detected_at.isoformat(),
        "explanation": f"Sir, I detected a {threat.severity.value} severity threat: {threat.description}"
    }
    
    return explanation
