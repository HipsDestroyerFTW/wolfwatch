"""Core scan execution logic shared by scheduler and manual triggers."""
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from ..models import MonitorTarget, ScanJob, ScanStatus, Finding, ThreatLevel, FindingCategory
from .crawler import run_scan_for_target, CrawlResult
from .analyzer import analyze_content

logger = logging.getLogger(__name__)


async def execute_scan(target_id: int, db: Session, triggered_by: str = "manual") -> ScanJob:
    """Run a full scan for a target and persist findings."""
    target: MonitorTarget | None = db.get(MonitorTarget, target_id)
    if not target:
        raise ValueError(f"Target {target_id} not found")

    # Create scan job record
    scan = ScanJob(
        target_id=target.id,
        status=ScanStatus.RUNNING,
        triggered_by=triggered_by,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info("Scan %d started for target %s (%s)", scan.id, target.name, target.value)

    try:
        crawl_results: list[CrawlResult] = await run_scan_for_target(
            target_value=target.value,
            target_type=target.target_type,
        )

        sources_checked = list({r.source_name for r in crawl_results})
        findings_created = 0

        for result in crawl_results:
            if not result.raw_content or result.error:
                continue

            analysis = await analyze_content(
                target_value=target.value,
                target_type=target.target_type,
                source_name=result.source_name,
                raw_content=result.raw_content,
                source_url=result.source_url,
            )

            threat_level = ThreatLevel(analysis.get("threat_level", "informational"))
            category     = FindingCategory(analysis.get("category", "other"))

            finding = Finding(
                target_id=target.id,
                scan_id=scan.id,
                title=analysis.get("title", f"Finding on {result.source_name}"),
                summary=analysis.get("summary", ""),
                raw_content=result.raw_content[:5000],
                source_url=result.source_url,
                source_name=result.source_name,
                threat_level=threat_level,
                category=category,
                risk_score=float(analysis.get("risk_score", 1.0)),
                ai_analysis=analysis.get("analysis", ""),
                extracted_data=analysis.get("extracted_data", {}),
            )
            db.add(finding)
            findings_created += 1

        # Update scan job
        now = datetime.now(timezone.utc)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = now
        scan.sources_checked = sources_checked
        scan.findings_count = findings_created

        # Update target metadata
        target.last_scanned_at = now
        target.next_scan_at = now + timedelta(hours=target.scan_interval_hours)

        # Recompute target risk score from recent findings
        if findings_created > 0:
            db.flush()
            recent_scores = [f.risk_score for f in db.query(Finding)
                             .filter(Finding.target_id == target.id,
                                     Finding.is_false_positive == False)  # noqa: E712
                             .order_by(Finding.first_seen_at.desc())
                             .limit(10).all()]
            if recent_scores:
                target.risk_score = round(max(recent_scores) * 0.7 + (sum(recent_scores) / len(recent_scores)) * 0.3, 2)

        db.commit()
        logger.info("Scan %d completed: %d finding(s) from %d source(s)", scan.id, findings_created, len(sources_checked))

    except Exception as exc:
        logger.error("Scan %d failed: %s", scan.id, exc, exc_info=True)
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()

    db.refresh(scan)
    return scan
