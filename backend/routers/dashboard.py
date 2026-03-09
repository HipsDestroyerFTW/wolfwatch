from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from ..database import get_db
from ..models import MonitorTarget, ScanJob, Finding, ThreatLevel
from ..schemas import DashboardStats, FindingOut
from ..services.analyzer import generate_threat_report

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

THREAT_ORDER = {
    ThreatLevel.CRITICAL: 5,
    ThreatLevel.HIGH: 4,
    ThreatLevel.MEDIUM: 3,
    ThreatLevel.LOW: 2,
    ThreatLevel.INFORMATIONAL: 1,
}


@router.get("/stats", response_model=DashboardStats)
def get_stats(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    total_targets  = db.query(func.count(MonitorTarget.id)).scalar() or 0
    active_targets = db.query(func.count(MonitorTarget.id)).filter(MonitorTarget.is_active == True).scalar() or 0  # noqa: E712

    total_findings = db.query(func.count(Finding.id)).filter(Finding.is_false_positive == False).scalar() or 0  # noqa: E712
    unacked = (db.query(func.count(Finding.id))
               .filter(Finding.is_acknowledged == False, Finding.is_false_positive == False)  # noqa: E712
               .scalar() or 0)
    critical = (db.query(func.count(Finding.id))
                .filter(Finding.threat_level == ThreatLevel.CRITICAL, Finding.is_false_positive == False)  # noqa: E712
                .scalar() or 0)
    high = (db.query(func.count(Finding.id))
            .filter(Finding.threat_level == ThreatLevel.HIGH, Finding.is_false_positive == False)  # noqa: E712
            .scalar() or 0)

    scans_24h = (db.query(func.count(ScanJob.id))
                 .filter(ScanJob.created_at >= day_ago)
                 .scalar() or 0)

    avg_risk = db.query(func.avg(MonitorTarget.risk_score)).scalar() or 0.0

    # Top threats by target
    top = (db.query(MonitorTarget.name, MonitorTarget.value, MonitorTarget.risk_score, MonitorTarget.target_type)
           .filter(MonitorTarget.risk_score > 0)
           .order_by(desc(MonitorTarget.risk_score))
           .limit(5).all())
    top_threats = [{"name": r.name, "value": r.value, "risk_score": round(r.risk_score, 2), "type": r.target_type} for r in top]

    # Recent findings
    recent_raw = (db.query(Finding)
                  .filter(Finding.is_false_positive == False)  # noqa: E712
                  .order_by(desc(Finding.first_seen_at))
                  .limit(10).all())
    recent_findings = [FindingOut.model_validate(f) for f in recent_raw]

    # Scan activity last 7 days (daily counts)
    week_ago = now - timedelta(days=7)
    activity_rows = (db.query(
        func.date(ScanJob.created_at).label("day"),
        func.count(ScanJob.id).label("count"),
    )
    .filter(ScanJob.created_at >= week_ago)
    .group_by(func.date(ScanJob.created_at))
    .all())
    scan_activity = [{"day": str(r.day), "count": r.count} for r in activity_rows]

    return DashboardStats(
        total_targets=total_targets,
        active_targets=active_targets,
        total_findings=total_findings,
        unacknowledged_findings=unacked,
        critical_findings=critical,
        high_findings=high,
        scans_last_24h=scans_24h,
        avg_risk_score=round(float(avg_risk), 2),
        top_threats=top_threats,
        recent_findings=recent_findings,
        scan_activity=scan_activity,
    )


@router.get("/report/{target_id}")
async def get_threat_report(target_id: int, db: Session = Depends(get_db)):
    target = db.get(MonitorTarget, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    findings = (db.query(Finding)
                .filter(Finding.target_id == target_id, Finding.is_false_positive == False)  # noqa: E712
                .order_by(desc(Finding.first_seen_at))
                .limit(20).all())

    findings_dicts = [
        {
            "title": f.title,
            "threat_level": f.threat_level,
            "category": f.category,
            "summary": f.summary,
            "source": f.source_name,
            "risk_score": f.risk_score,
            "found_at": str(f.first_seen_at),
        }
        for f in findings
    ]

    report = await generate_threat_report(
        findings=findings_dicts,
        target={"name": target.name, "value": target.value, "target_type": target.target_type},
    )
    return {"target_id": target_id, "target_name": target.name, "report": report}
