"""
Threats API Endpoints
"""
from fastapi import APIRouter, Query
from typing import List, Optional
from datetime import datetime
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.storage import threats_db

router = APIRouter()


@router.get("/threats", response_model=List[ThreatEvent])
async def list_threats(
    severity: Optional[ThreatSeverity] = None,
    threat_type: Optional[ThreatType] = None,
    resolved: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """List all threats with optional filtering"""
    filtered = threats_db
    
    if severity:
        filtered = [t for t in filtered if t.severity == severity]
    if threat_type:
        filtered = [t for t in filtered if t.threat_type == threat_type]
    if resolved is not None:
        filtered = [t for t in filtered if t.resolved == resolved]
    
    return filtered[:limit]


@router.get("/threats/{threat_id}", response_model=ThreatEvent)
async def get_threat(threat_id: str):
    """Get threat details by ID"""
    from uuid import UUID
    threat_id_uuid = UUID(threat_id)
    
    for threat in threats_db:
        if threat.id == threat_id_uuid:
            return threat
    
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Threat not found")


@router.post("/threats/{threat_id}/resolve")
async def resolve_threat(threat_id: str):
    """Mark a threat as resolved"""
    from uuid import UUID
    from fastapi import HTTPException
    
    threat_id_uuid = UUID(threat_id)
    
    for threat in threats_db:
        if threat.id == threat_id_uuid:
            threat.resolved = True
            threat.resolved_at = datetime.utcnow()
            return {"status": "resolved", "threat_id": str(threat.id)}
    
    raise HTTPException(status_code=404, detail="Threat not found")
