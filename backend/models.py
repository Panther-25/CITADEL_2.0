import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class UserRole(str, Enum):
    PLATFORM_SUPER_ADMIN = "PLATFORM_SUPER_ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"

class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"

class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AlertStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"

# ==================== TENANCY & USERS ====================
class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False, unique=True)
    is_active = Column(Boolean, default=True, nullable=False)
    retention_days = Column(Integer, default=90, nullable=False)
    security_policy = Column(JSON, default=dict)  # MFA enforced, IP restrictions, etc.
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    cloud_accounts = relationship("CloudAccount", back_populates="organization", cascade="all, delete-orphan")
    events = relationship("SecurityEvent", back_populates="organization")
    alerts = relationship("ThreatAlert", back_populates="organization")

class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True) # Null for SuperAdmin
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(64), default=UserRole.VIEWER.value, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Security & MFA
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(128), nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="users")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String(64), primary_key=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String(512), unique=True, nullable=False, index=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="sessions")

# ==================== CLOUD INTEGRATION & LOGS ====================
class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(32), default="AWS", nullable=False)
    account_id = Column(String(64), nullable=False)
    account_name = Column(String(128), nullable=False)
    role_arn = Column(String(255), nullable=True)
    external_id = Column(String(128), nullable=True)
    is_connected = Column(Boolean, default=True, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="cloud_accounts")

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    cloud_account_id = Column(String(64), ForeignKey("cloud_accounts.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_name = Column(String(128), nullable=False, index=True)
    event_source = Column(String(128), nullable=False)
    aws_region = Column(String(64), nullable=True)
    source_ip = Column(String(64), nullable=True, index=True)
    user_identity = Column(JSON, nullable=False)
    user_agent = Column(String(255), nullable=True)
    error_code = Column(String(64), nullable=True)
    raw_payload = Column(JSON, nullable=False)
    
    # Anomaly / Score cached
    anomaly_score = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="events")

    __table_args__ = (
        Index("idx_org_time", "org_id", "timestamp"),
        Index("idx_org_event", "org_id", "event_name"),
    )

# ==================== ALERTS, DETECTIONS & INVESTIGATIONS ====================
class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), default=AlertSeverity.HIGH.value, nullable=False)
    status = Column(String(32), default=AlertStatus.NEW.value, nullable=False)
    anomaly_score = Column(Float, default=0.0, nullable=False)
    detection_type = Column(String(64), nullable=False)  # ISOLATION_FOREST, BEHAVIORAL_SEQUENCE, RULE_BASED
    explanation = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False)  # array of event ids, suspicious attributes, confidence factors
    ai_remediation_plan = Column(JSON, nullable=True) # { recommended_actions: [], dry_run_diff: str, risk_level: str }
    remediation_status = Column(String(32), default="PENDING_APPROVAL") # PENDING_APPROVAL, APPROVED, EXECUTED, REJECTED
    correlated_events_count = Column(Integer, default=1)
    assigned_to = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="alerts")
    investigations = relationship("InvestigationCase", back_populates="alert")

class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(64), ForeignKey("threat_alerts.id", ondelete="CASCADE"), nullable=False)
    lead_analyst_id = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=True)
    status = Column(String(32), default="OPEN", nullable=False)
    evidence_timeline = Column(JSON, default=list) # [{time, event, note, user}]
    analyst_notes = Column(JSON, default=list)
    mitigation_actions = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    alert = relationship("ThreatAlert", back_populates="investigations")

# ==================== TAMPER-EVIDENT AUDIT & PRIVILEGED APPROVALS ====================
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), nullable=True, index=True) # None if platform-wide superadmin
    actor_id = Column(String(64), nullable=False)
    actor_email = Column(String(255), nullable=False)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=True)
    details = Column(JSON, default=dict)
    outcome = Column(String(32), default="SUCCESS")  # SUCCESS, DENIED, FAILED
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)

class PrivilegedApproval(Base):
    __tablename__ = "privileged_approvals"

    id = Column(String(64), primary_key=True)
    org_id = Column(String(64), nullable=True)
    requester_id = Column(String(64), nullable=False)
    requester_email = Column(String(255), nullable=False)
    action = Column(String(128), nullable=False)
    justification = Column(Text, nullable=False)
    target_resource = Column(String(255), nullable=False)
    status = Column(String(32), default=ApprovalStatus.PENDING.value, nullable=False)
    approver_id = Column(String(64), nullable=True)
    approver_email = Column(String(255), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class ModelRegistry(Base):
    __tablename__ = "model_registry"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    version = Column(String(32), nullable=False)
    algorithm = Column(String(64), default="IsolationForest", nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    parameters = Column(JSON, default=dict)
    metrics = Column(JSON, default=dict) # precision, recall, anomaly_threshold
    created_by = Column(String(64), nullable=False)
    approved_by = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
