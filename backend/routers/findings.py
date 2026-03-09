from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from ..database import get_db
from ..models import Finding, ThreatLevel, FindingCategory
from ..schemas import FindingOut, FindingAcknowledge

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    target_id: Optional[int] = Query(None),
    threat_level: Optional[ThreatLevel] = Query(None),
    category: Optional[FindingCategory] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    false_positive: bool = Query(False),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db),
):
    q = db.query(Finding).filter(Finding.is_false_positive == false_positive)

    if target_id is not None:
        q = q.filter(Finding.target_id == target_id)
    if threat_level:
        q = q.filter(Finding.threat_level == threat_level)
    if category:
        q = q.filter(Finding.category == category)
    if acknowledged is not None:
        q = q.filter(Finding.is_acknowledged == acknowledged)

    return q.order_by(desc(Finding.first_seen_at)).offset(offset).limit(limit).all()


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@router.patch("/{finding_id}/acknowledge", response_model=FindingOut)
def acknowledge_finding(finding_id: int, payload: FindingAcknowledge, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.is_acknowledged = payload.is_acknowledged
    f.is_false_positive = payload.is_false_positive
    db.commit()
    db.refresh(f)
    return f


@router.delete("/{finding_id}", status_code=204)
def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(f)
    db.commit()
