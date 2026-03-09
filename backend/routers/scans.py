import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import MonitorTarget, ScanJob, ScanStatus
from ..schemas import ScanJobOut
from ..services.scan_runner import execute_scan

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.get("", response_model=list[ScanJobOut])
def list_scans(
    target_id: int | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(ScanJob)
    if target_id:
        q = q.filter(ScanJob.target_id == target_id)
    return q.order_by(ScanJob.created_at.desc()).limit(limit).all()


@router.get("/{scan_id}", response_model=ScanJobOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(ScanJob, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/trigger/{target_id}", response_model=ScanJobOut, status_code=202)
async def trigger_scan(
    target_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    target = db.get(MonitorTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.is_active:
        raise HTTPException(status_code=400, detail="Target is paused — activate it first")

    # Check if already running
    running = db.query(ScanJob).filter(
        ScanJob.target_id == target_id,
        ScanJob.status == ScanStatus.RUNNING,
    ).first()
    if running:
        raise HTTPException(status_code=409, detail=f"Scan {running.id} is already running for this target")

    # Run in background so we can return immediately
    async def _bg():
        from ..database import SessionLocal
        db2 = SessionLocal()
        try:
            await execute_scan(target_id, db2, triggered_by="manual")
        finally:
            db2.close()

    background_tasks.add_task(_bg)

    # Return a pending placeholder the UI can poll
    from ..models import ScanJob as SJ
    from datetime import datetime, timezone
    pending = SJ(
        target_id=target_id,
        status=ScanStatus.PENDING,
        triggered_by="manual",
    )
    db.add(pending)
    db.commit()
    db.refresh(pending)
    return pending
