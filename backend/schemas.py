from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, field_validator
from .models import TargetType, ScanStatus, ThreatLevel, FindingCategory


# ─── Target ──────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    name: str
    target_type: TargetType
    value: str
    description: Optional[str] = None
    scan_interval_hours: int = 6
    tags: list[str] = []

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        return v.strip().lower()


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    scan_interval_hours: Optional[int] = None
    tags: Optional[list[str]] = None


class TargetOut(BaseModel):
    id: int
    name: str
    target_type: TargetType
    value: str
    description: Optional[str]
    is_active: bool
    scan_interval_hours: int
    last_scanned_at: Optional[datetime]
    next_scan_at: Optional[datetime]
    risk_score: float
    tags: list[str]
    created_at: datetime
    findings_count: Optional[int] = 0

    model_config = {"from_attributes": True}


# ─── Scan ─────────────────────────────────────────────────────────────────────

class ScanJobOut(BaseModel):
    id: int
    target_id: int
    status: ScanStatus
    triggered_by: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]
    sources_checked: list[str]
    findings_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Finding ─────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: int
    target_id: int
    scan_id: int
    title: str
    summary: str
    source_url: Optional[str]
    source_name: Optional[str]
    threat_level: ThreatLevel
    category: FindingCategory
    risk_score: float
    ai_analysis: Optional[str]
    extracted_data: dict[str, Any]
    is_acknowledged: bool
    is_false_positive: bool
    first_seen_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingAcknowledge(BaseModel):
    is_acknowledged: bool
    is_false_positive: bool = False


# ─── Dashboard ───────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_targets: int
    active_targets: int
    total_findings: int
    unacknowledged_findings: int
    critical_findings: int
    high_findings: int
    scans_last_24h: int
    avg_risk_score: float
    top_threats: list[dict]
    recent_findings: list[FindingOut]
    scan_activity: list[dict]


# ─── Alert Rule ──────────────────────────────────────────────────────────────

class AlertRuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    min_threat_level: ThreatLevel = ThreatLevel.HIGH
    target_types: list[TargetType] = []
    categories: list[FindingCategory] = []
    notify_email: Optional[str] = None


class AlertRuleOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    min_threat_level: ThreatLevel
    target_types: list[str]
    categories: list[str]
    notify_email: Optional[str]
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
