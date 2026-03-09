from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from ..models import MonitorTarget, Finding
from ..schemas import TargetCreate, TargetUpdate, TargetOut
from ..config import settings

router = APIRouter(prefix="/targets", tags=["Targets"])


def _enrich(target: MonitorTarget, db: Session) -> TargetOut:
    count = db.query(func.count(Finding.id)).filter(Finding.target_id == target.id).scalar() or 0
    out = TargetOut.model_validate(target)
    out.findings_count = count
    return out


@router.get("", response_model=list[TargetOut])
def list_targets(
    active_only: bool = Query(False),
    target_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(MonitorTarget)
    if active_only:
        q = q.filter(MonitorTarget.is_active == True)  # noqa: E712
    if target_type:
        q = q.filter(MonitorTarget.target_type == target_type)
    targets = q.order_by(MonitorTarget.risk_score.desc()).all()
    return [_enrich(t, db) for t in targets]


@router.post("", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    existing = db.query(MonitorTarget).filter(
        MonitorTarget.value == payload.value,
        MonitorTarget.target_type == payload.target_type,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Target with this value and type already exists")

    target = MonitorTarget(
        **payload.model_dump(),
        next_scan_at=datetime.now(timezone.utc),  # queue immediately
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return _enrich(target, db)


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(MonitorTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return _enrich(target, db)


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(target_id: int, payload: TargetUpdate, db: Session = Depends(get_db)):
    target = db.get(MonitorTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(target, field, value)

    db.commit()
    db.refresh(target)
    return _enrich(target, db)


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(MonitorTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()


@router.post("/{target_id}/toggle", response_model=TargetOut)
def toggle_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(MonitorTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    target.is_active = not target.is_active
    if target.is_active:
        target.next_scan_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(target)
    return _enrich(target, db)
