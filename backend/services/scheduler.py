"""Background scheduler for automatic target scanning."""
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session
from ..database import SessionLocal
from ..models import MonitorTarget, ScanJob, ScanStatus
from .scan_runner import execute_scan

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="UTC")
_scan_semaphore: asyncio.Semaphore | None = None


def get_semaphore(max_concurrent: int = 3) -> asyncio.Semaphore:
    global _scan_semaphore
    if _scan_semaphore is None:
        _scan_semaphore = asyncio.Semaphore(max_concurrent)
    return _scan_semaphore


async def _scan_due_targets():
    """Find targets due for scanning and dispatch scan jobs."""
    from ..config import settings

    db: Session = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        targets = (
            db.query(MonitorTarget)
            .filter(
                MonitorTarget.is_active == True,  # noqa: E712
                (MonitorTarget.next_scan_at == None) | (MonitorTarget.next_scan_at <= now),
            )
            .all()
        )

        if not targets:
            return

        logger.info("Scheduler: %d target(s) due for scanning", len(targets))
        sem = get_semaphore(settings.MAX_CONCURRENT_CRAWLS)

        async def _run_one(target_id: int):
            async with sem:
                db2: Session = SessionLocal()
                try:
                    await execute_scan(target_id, db2, triggered_by="scheduler")
                finally:
                    db2.close()

        await asyncio.gather(*[_run_one(t.id) for t in targets])
    except Exception as exc:
        logger.error("Scheduler error: %s", exc)
    finally:
        db.close()


def start_scheduler():
    if not scheduler.running:
        scheduler.add_job(
            _scan_due_targets,
            trigger=IntervalTrigger(minutes=15),
            id="scan_due_targets",
            replace_existing=True,
            max_instances=1,
        )
        scheduler.start()
        logger.info("APScheduler started — checking for due scans every 15 minutes")


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")
