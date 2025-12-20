"""
Threats API Endpoints
"""
from fastapi import APIRouter, Query
from typing import List, Optional
from datetime import datetime
from app.models.threat_event import ThreatEvent, ThreatSeverity, ThreatType
from app.storage import get_threats_db

router = APIRouter()


@router.get("/threats", response_model=List[ThreatEvent])
async def list_threats(
    severity: Optional[ThreatSeverity] = None,
    threat_type: Optional[ThreatType] = None,
    resolved: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """List all threats with optional filtering"""
    threats_db = get_threats_db()
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
    
    threats_db = get_threats_db()
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
    
    # Update in database if using database
    from app.storage import USE_DATABASE
    if USE_DATABASE:
        from app.database.connection import SessionLocal
        from app.database.models import ThreatEventDB
        db = SessionLocal()
        try:
            threat_db = db.query(ThreatEventDB).filter(ThreatEventDB.id == threat_id_uuid).first()
            if threat_db:
                threat_db.resolved = True
                threat_db.resolved_at = datetime.utcnow()
                db.commit()
                return {"status": "resolved", "threat_id": str(threat_db.id)}
        finally:
            db.close()
    
    # Fallback to in-memory
    threats_db = get_threats_db()
    for threat in threats_db:
        if threat.id == threat_id_uuid:
            threat.resolved = True
            threat.resolved_at = datetime.utcnow()
            # Update in storage
            from app.storage import add_threat
            add_threat(threat)
            return {"status": "resolved", "threat_id": str(threat.id)}
    
    raise HTTPException(status_code=404, detail="Threat not found")
