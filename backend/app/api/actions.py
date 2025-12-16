"""
Remediation Actions API Endpoints
"""
from fastapi import APIRouter, Query
from typing import List, Optional
from app.models.remediation_action import RemediationAction, ActionType
from app.storage import actions_db

router = APIRouter()


@router.get("/actions", response_model=List[RemediationAction])
async def list_actions(
    action_type: Optional[ActionType] = None,
    executed: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000)
):
    """List all remediation actions"""
    filtered = actions_db
    
    if action_type:
        filtered = [a for a in filtered if a.action_type == action_type]
    if executed is not None:
        filtered = [a for a in filtered if a.executed == executed]
    
    return filtered[:limit]


@router.get("/actions/{action_id}", response_model=RemediationAction)
async def get_action(action_id: str):
    """Get action details by ID"""
    from uuid import UUID
    from fastapi import HTTPException
    
    action_id_uuid = UUID(action_id)
    
    for action in actions_db:
        if action.id == action_id_uuid:
            return action
    
    raise HTTPException(status_code=404, detail="Action not found")
