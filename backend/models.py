from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, Float, Enum, JSON
)
from sqlalchemy.orm import relationship
from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class TargetType(str, PyEnum):
    DOMAIN = "domain"
    EMAIL = "email"
    KEYWORD = "keyword"
    ONION_URL = "onion_url"
    IP_ADDRESS = "ip_address"
    BRAND = "brand"


class ScanStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ThreatLevel(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingCategory(str, PyEnum):
    CREDENTIAL_LEAK = "credential_leak"
    DATA_BREACH = "data_breach"
    BRAND_MENTION = "brand_mention"
    INFRASTRUCTURE_EXPOSURE = "infrastructure_exposure"
    THREAT_ACTOR = "threat_actor"
    FRAUD = "fraud"
    OTHER = "other"


class MonitorTarget(Base):
    __tablename__ = "monitor_targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target_type = Column(Enum(TargetType), nullable=False)
    value = Column(String(1024), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    scan_interval_hours = Column(Integer, default=6, nullable=False)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    next_scan_at = Column(DateTime(timezone=True), nullable=True)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    tags = Column(JSON, default=list)

    scans = relationship("ScanJob", back_populates="target", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("monitor_targets.id", ondelete="CASCADE"), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    triggered_by = Column(String(50), default="scheduler")  # scheduler | manual
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    sources_checked = Column(JSON, default=list)
    findings_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    target = relationship("MonitorTarget", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("monitor_targets.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(512), nullable=False)
    summary = Column(Text, nullable=False)
    raw_content = Column(Text, nullable=True)
    source_url = Column(String(2048), nullable=True)
    source_name = Column(String(255), nullable=True)
    threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.INFORMATIONAL, nullable=False)
    category = Column(Enum(FindingCategory), default=FindingCategory.OTHER, nullable=False)
    risk_score = Column(Float, default=0.0)
    ai_analysis = Column(Text, nullable=True)
    extracted_data = Column(JSON, default=dict)   # emails, passwords, IPs found
    is_acknowledged = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    target = relationship("MonitorTarget", back_populates="findings")
    scan = relationship("ScanJob", back_populates="findings")


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    min_threat_level = Column(Enum(ThreatLevel), default=ThreatLevel.HIGH, nullable=False)
    target_types = Column(JSON, default=list)  # empty = all types
    categories = Column(JSON, default=list)    # empty = all categories
    notify_email = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
