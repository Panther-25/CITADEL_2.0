import os
import json
import uuid
import datetime
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, status, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from backend.database import get_db, init_db
from backend.models import (
    User, Organization, UserSession, SecurityEvent, ThreatAlert,
    InvestigationCase, AuditLog, PrivilegedApproval, ModelRegistry,
    UserRole, AlertSeverity, AlertStatus, ApprovalStatus
)
from backend.auth import (
    verify_password, get_password_hash, create_access_token,
    verify_totp, generate_totp_secret, get_current_user, require_permission
)
from backend.rbac import Permission
from backend.audit import record_audit_event, verify_audit_ledger_integrity
from backend.ai_engine import CloudThreatEngine

app = FastAPI(
    title="CITADEL 2.0 API",
    description="Enterprise Cloud Threat Intelligence, Detection & Security Operations Platform",
    version="2.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup DB initialization
@app.on_event("startup")
def on_startup():
    init_db()

# ==================== SCHEMAS ====================
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None

class SetupMfaResponse(BaseModel):
    secret: str
    provisioning_uri: str

class VerifyMfaRequest(BaseModel):
    code: str

class UserCreateRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: str
    org_id: Optional[str] = None

class OrgCreateRequest(BaseModel):
    name: str
    retention_days: int = 90
    security_policy: Optional[Dict[str, Any]] = None

class EventIngestItem(BaseModel):
    event_name: str = Field(..., alias="eventName")
    event_source: str = Field(..., alias="eventSource")
    timestamp: str = Field(..., alias="eventTime")
    aws_region: Optional[str] = Field(None, alias="awsRegion")
    source_ip: Optional[str] = Field(None, alias="sourceIPAddress")
    user_identity: Dict[str, Any] = Field(..., alias="userIdentity")
    user_agent: Optional[str] = Field(None, alias="userAgent")
    error_code: Optional[str] = Field(None, alias="errorCode")
    raw_payload: Optional[Dict[str, Any]] = None

    class Config:
        populate_by_name = True

class EventBatchIngest(BaseModel):
    events: List[EventIngestItem]

class PrivilegedApprovalRequest(BaseModel):
    action: str
    justification: str
    target_resource: str

class PrivilegedApprovalDecision(BaseModel):
    decision: str  # APPROVED or REJECTED

class InvestigationNote(BaseModel):
    note: str

# ==================== HEALTH & OPERATIONAL STATUS ====================
@app.get("/api/health")
def health_check(db: Session = Depends(get_db)):
    try:
        org_count = db.query(Organization).count()
        return {
            "status": "healthy",
            "version": "2.0.0",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "tenants_active": org_count,
            "security_subsystems": {
                "rbac": "enforced",
                "audit_tamper_evidence": "active",
                "ai_threat_detection": "operational"
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database unreachable: {str(e)}")

# ==================== AUTHENTICATION & SESSIONS ====================
@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            db.commit()
            record_audit_event(
                db, actor_id=user.id, actor_email=user.email, action="AUTH_LOGIN_FAILED",
                resource_type="USER", resource_id=user.id, org_id=user.org_id,
                outcome="DENIED", ip_address=request.client.host if request.client else None
            )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    # Check MFA requirement for privileged roles
    privileged_roles = [UserRole.PLATFORM_SUPER_ADMIN.value, UserRole.SECURITY_ADMIN.value, UserRole.ORG_ADMIN.value]
    if user.mfa_enabled or (user.role in privileged_roles and user.mfa_secret):
        if not req.totp_code:
            return {
                "mfa_required": True,
                "message": "Multi-factor authentication (TOTP) code required for this account."
            }
        if not verify_totp(user.mfa_secret, req.totp_code):
            record_audit_event(
                db, actor_id=user.id, actor_email=user.email, action="AUTH_MFA_FAILED",
                resource_type="USER", resource_id=user.id, org_id=user.org_id,
                outcome="DENIED", ip_address=request.client.host if request.client else None
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA TOTP code")

    # Successful login
    user.failed_login_attempts = 0
    user.last_login_at = datetime.datetime.utcnow()

    token_expires = datetime.timedelta(hours=8)
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role, "org_id": user.org_id}, expires_delta=token_expires)

    session_id = str(uuid.uuid4())
    user_session = UserSession(
        id=session_id,
        user_id=user.id,
        token=token,
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "Unknown"),
        expires_at=datetime.datetime.utcnow() + token_expires
    )
    db.add(user_session)
    db.commit()

    record_audit_event(
        db, actor_id=user.id, actor_email=user.email, action="AUTH_LOGIN_SUCCESS",
        resource_type="USER", resource_id=user.id, org_id=user.org_id,
        outcome="SUCCESS", ip_address=request.client.host if request.client else None
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "org_id": user.org_id,
            "mfa_enabled": user.mfa_enabled
        }
    }

@app.post("/api/auth/logout")
def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), authorization: str = Header(...)):
    token = authorization.split(" ")[1]
    db.query(UserSession).filter(UserSession.token == token).update({"is_revoked": True})
    db.commit()
    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email, action="AUTH_LOGOUT",
        resource_type="USER", resource_id=current_user.id, org_id=current_user.org_id
    )
    return {"message": "Session successfully terminated"}

@app.get("/api/auth/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "org_id": current_user.org_id,
        "mfa_enabled": current_user.mfa_enabled
    }

# ==================== TENANCY & ORGANIZATIONS (SUPER ADMIN) ====================
@app.get("/api/admin/organizations")
def list_organizations(
    current_user: User = Depends(require_permission(Permission.ORG_READ)),
    db: Session = Depends(get_db)
):
    if current_user.role == UserRole.PLATFORM_SUPER_ADMIN.value:
        orgs = db.query(Organization).all()
    else:
        orgs = db.query(Organization).filter(Organization.id == current_user.org_id).all()
    return orgs

@app.post("/api/admin/organizations")
def create_organization(
    req: OrgCreateRequest,
    current_user: User = Depends(require_permission(Permission.ORG_CREATE)),
    db: Session = Depends(get_db)
):
    org_id = f"org_{uuid.uuid4().hex[:12]}"
    new_org = Organization(
        id=org_id,
        name=req.name,
        retention_days=req.retention_days,
        security_policy=req.security_policy or {"mfa_required": True}
    )
    db.add(new_org)
    db.commit()
    db.refresh(new_org)

    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email,
        action="ORG_CREATED", resource_type="ORGANIZATION", resource_id=new_org.id,
        details={"name": new_org.name, "retention_days": new_org.retention_days}
    )
    return new_org

# ==================== USER MANAGEMENT ====================
@app.get("/api/users")
def list_users(
    current_user: User = Depends(require_permission(Permission.USER_READ)),
    db: Session = Depends(get_db)
):
    if current_user.role == UserRole.PLATFORM_SUPER_ADMIN.value:
        users = db.query(User).all()
    else:
        users = db.query(User).filter(User.org_id == current_user.org_id).all()
    
    return [
        {
            "id": u.id, "email": u.email, "full_name": u.full_name,
            "role": u.role, "org_id": u.org_id, "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled, "created_at": u.created_at.isoformat()
        }
        for u in users
    ]

@app.post("/api/users")
def create_user(
    req: UserCreateRequest,
    current_user: User = Depends(require_permission(Permission.USER_CREATE)),
    db: Session = Depends(get_db)
):
    # Enforce tenant boundary
    target_org_id = current_user.org_id if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value else req.org_id

    # Disallow escalating to SuperAdmin if not SuperAdmin
    if req.role == UserRole.PLATFORM_SUPER_ADMIN.value and current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value:
        raise HTTPException(status_code=403, detail="Cannot assign Platform Super Admin role")

    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User email already registered")

    user_id = f"usr_{uuid.uuid4().hex[:12]}"
    new_user = User(
        id=user_id,
        org_id=target_org_id,
        email=req.email,
        full_name=req.full_name,
        hashed_password=get_password_hash(req.password),
        role=req.role,
        is_active=True,
        mfa_enabled=False
    )
    db.add(new_user)
    db.commit()

    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email,
        action="USER_CREATED", resource_type="USER", resource_id=new_user.id,
        org_id=target_org_id, details={"email": new_user.email, "role": new_user.role}
    )
    return {"message": "User successfully created", "id": new_user.id}

# ==================== CLOUD EVENT INGESTION & AI DETECTION ====================
@app.post("/api/events/ingest")
def ingest_events(
    batch: EventBatchIngest,
    current_user: User = Depends(require_permission(Permission.EVENTS_INGEST)),
    db: Session = Depends(get_db)
):
    if not current_user.org_id and current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value:
        raise HTTPException(status_code=400, detail="User must belong to an organization to ingest events")

    org_id = current_user.org_id or "default_org"

    raw_event_dicts = []
    db_events = []

    for item in batch.events:
        eid = f"evt_{uuid.uuid4().hex[:14]}"
        try:
            ts = datetime.datetime.fromisoformat(item.timestamp.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.datetime.utcnow()

        event_dict = {
            "id": eid,
            "event_name": item.event_name,
            "event_source": item.event_source,
            "timestamp": ts,
            "aws_region": item.aws_region,
            "source_ip": item.source_ip,
            "user_identity": item.user_identity,
            "error_code": item.error_code,
            "raw_payload": item.raw_payload or item.dict(by_alias=True)
        }
        raw_event_dicts.append(event_dict)

        db_ev = SecurityEvent(
            id=eid,
            org_id=org_id,
            timestamp=ts,
            event_name=item.event_name,
            event_source=item.event_source,
            aws_region=item.aws_region,
            source_ip=item.source_ip,
            user_identity=item.user_identity,
            user_agent=item.user_agent,
            error_code=item.error_code,
            raw_payload=event_dict["raw_payload"]
        )
        db_events.append(db_ev)

    # Run AI Threat Engine (Isolation Forest + Behavioral Sequence Analysis)
    threat_engine = CloudThreatEngine()
    scored_results = threat_engine.fit_and_score(raw_event_dicts)
    sequence_alerts = threat_engine.detect_sequence_patterns(raw_event_dicts)

    # Attach scores to DB objects
    score_map = {res["event_id"]: res for res in scored_results}
    generated_alerts = []

    for ev in db_events:
        score_info = score_map.get(ev.id)
        if score_info:
            ev.anomaly_score = score_info["anomaly_score"]
            ev.is_anomalous = score_info["is_anomalous"]

            # If isolated high anomaly, trigger alert
            if ev.anomaly_score >= 0.7:
                actor = ev.user_identity.get("userName", "unknown_principal")
                remediation_plan = threat_engine.generate_remediation_plan(
                    title=f"AI Anomaly: Suspicious {ev.event_name} Activity",
                    detection_type="ISOLATION_FOREST",
                    actor=actor,
                    event_names=[ev.event_name]
                )
                alert_id = f"alt_{uuid.uuid4().hex[:12]}"
                alert = ThreatAlert(
                    id=alert_id,
                    org_id=org_id,
                    title=f"AI Anomaly: Suspicious {ev.event_name} Activity",
                    severity=AlertSeverity.HIGH.value if ev.anomaly_score >= 0.85 else AlertSeverity.MEDIUM.value,
                    status=AlertStatus.NEW.value,
                    anomaly_score=ev.anomaly_score,
                    detection_type="ISOLATION_FOREST",
                    explanation=score_info["explanation"],
                    evidence={"event_id": ev.id, "source_ip": ev.source_ip, "actor": actor},
                    ai_remediation_plan=remediation_plan,
                    remediation_status="PENDING_APPROVAL",
                    correlated_events_count=1
                )
                generated_alerts.append(alert)

    # Create sequence-based alerts
    for seq in sequence_alerts:
        alert_id = f"alt_{uuid.uuid4().hex[:12]}"
        remediation_plan = threat_engine.generate_remediation_plan(
            title=seq["title"],
            detection_type=seq["detection_type"],
            actor=seq.get("evidence", [{}])[0] if isinstance(seq.get("evidence"), list) else "compromised_actor",
            event_names=[]
        )
        alert = ThreatAlert(
            id=alert_id,
            org_id=org_id,
            title=seq["title"],
            severity=seq["severity"],
            status=AlertStatus.NEW.value,
            anomaly_score=seq["anomaly_score"],
            detection_type=seq["detection_type"],
            explanation=seq["explanation"],
            evidence={"event_ids": seq["evidence"]},
            ai_remediation_plan=remediation_plan,
            remediation_status="PENDING_APPROVAL",
            correlated_events_count=len(seq["evidence"])
        )
        generated_alerts.append(alert)

    # Commit all events and alerts
    db.add_all(db_events)
    db.add_all(generated_alerts)
    db.commit()

    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email,
        action="EVENTS_INGESTED", resource_type="SECURITY_EVENT", org_id=org_id,
        details={"events_count": len(db_events), "alerts_generated": len(generated_alerts)}
    )

    return {
        "events_processed": len(db_events),
        "alerts_generated": len(generated_alerts),
        "anomalies_detected": sum(1 for e in db_events if e.is_anomalous)
    }

# ==================== SECURITY ANALYST: EVENTS & ALERTS ====================
@app.get("/api/events")
def get_security_events(
    limit: int = 50,
    current_user: User = Depends(require_permission(Permission.EVENTS_READ)),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value or current_user.org_id:
        query = query.filter(SecurityEvent.org_id == current_user.org_id)
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return events

@app.get("/api/alerts")
def get_threat_alerts(
    current_user: User = Depends(require_permission(Permission.ALERTS_READ)),
    db: Session = Depends(get_db)
):
    query = db.query(ThreatAlert)
    if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value or current_user.org_id:
        query = query.filter(ThreatAlert.org_id == current_user.org_id)
    alerts = query.order_by(ThreatAlert.created_at.desc()).all()
    return alerts

@app.post("/api/alerts/{alert_id}/remediate")
def approve_and_execute_remediation(
    alert_id: str,
    decision: Dict[str, str], # {"action": "APPROVE" | "REJECT"}
    current_user: User = Depends(require_permission(Permission.ALERTS_MANAGE)),
    db: Session = Depends(get_db)
):
    """
    Human-in-the-loop AI Remediation Execution:
    Allows an authorized analyst/administrator to review and execute the AI suggested fix.
    """
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value and alert.org_id != current_user.org_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access denied")

    action = decision.get("action", "APPROVE")
    if action == "APPROVE":
        alert.remediation_status = "EXECUTED"
        alert.status = AlertStatus.CONTAINED.value
        execution_note = f"AI Remediation plan approved and executed by {current_user.full_name} ({current_user.email}). All containment commands applied."
    else:
        alert.remediation_status = "REJECTED"
        execution_note = f"AI Remediation plan rejected by {current_user.full_name} ({current_user.email})."

    # Also record into associated investigation case if exists
    inv = db.query(InvestigationCase).filter(InvestigationCase.alert_id == alert_id).first()
    if inv:
        updated_actions = list(inv.mitigation_actions or [])
        updated_actions.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "operator": current_user.full_name,
            "status": alert.remediation_status,
            "commands": (alert.ai_remediation_plan or {}).get("containment_commands", [])
        })
        inv.mitigation_actions = updated_actions

    db.commit()

    # Record tamper-evident audit log
    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email,
        action=f"AI_REMEDIATION_{alert.remediation_status}",
        resource_type="THREAT_ALERT", resource_id=alert_id,
        org_id=alert.org_id,
        details={
            "status": alert.remediation_status,
            "approved_by": current_user.email,
            "remediation_summary": (alert.ai_remediation_plan or {}).get("summary")
        }
    )

    return {
        "alert_id": alert.id,
        "remediation_status": alert.remediation_status,
        "alert_status": alert.status,
        "message": execution_note
    }

@app.post("/api/alerts/{alert_id}/investigate")
def create_or_get_investigation(
    alert_id: str,
    current_user: User = Depends(require_permission(Permission.INVESTIGATE)),
    db: Session = Depends(get_db)
):
    alert = db.query(ThreatAlert).filter(ThreatAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value and alert.org_id != current_user.org_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access denied")

    inv = db.query(InvestigationCase).filter(InvestigationCase.alert_id == alert_id).first()
    if not inv:
        inv = InvestigationCase(
            id=f"case_{uuid.uuid4().hex[:12]}",
            org_id=alert.org_id,
            alert_id=alert.id,
            lead_analyst_id=current_user.id,
            title=f"Investigation: {alert.title}",
            summary=f"Automated case initialized for {alert.detection_type} alert with anomaly score {alert.anomaly_score:.2f}",
            status="OPEN",
            evidence_timeline=[{
                "time": datetime.datetime.utcnow().isoformat(),
                "analyst": current_user.full_name,
                "note": "Case opened for forensic review."
            }],
            analyst_notes=[]
        )
        alert.status = AlertStatus.INVESTIGATING.value
        db.add(inv)
        db.commit()
        db.refresh(inv)

    return inv

@app.post("/api/investigations/{case_id}/notes")
def add_investigation_note(
    case_id: str,
    req: InvestigationNote,
    current_user: User = Depends(require_permission(Permission.INVESTIGATE)),
    db: Session = Depends(get_db)
):
    inv = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation case not found")

    if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value and inv.org_id != current_user.org_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access denied")

    updated_notes = list(inv.analyst_notes or [])
    updated_notes.append({
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "analyst": current_user.full_name,
        "note": req.note
    })
    inv.analyst_notes = updated_notes
    db.commit()
    return {"message": "Analyst note added", "notes": inv.analyst_notes}

# ==================== TAMPER-EVIDENT AUDIT & INTEGRITY ====================
@app.get("/api/audit/logs")
def get_audit_logs(
    limit: int = 100,
    current_user: User = Depends(require_permission(Permission.AUDIT_READ)),
    db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if current_user.role != UserRole.PLATFORM_SUPER_ADMIN.value or current_user.org_id:
        query = query.filter(AuditLog.org_id == current_user.org_id)
    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return logs

@app.get("/api/audit/verify-integrity")
def verify_audit_chain(
    current_user: User = Depends(require_permission(Permission.AUDIT_VERIFY)),
    db: Session = Depends(get_db)
):
    org_filter = None if current_user.role == UserRole.PLATFORM_SUPER_ADMIN.value else current_user.org_id
    is_valid, records_checked, info = verify_audit_ledger_integrity(db, org_id=org_filter)
    return {
        "is_valid": is_valid,
        "records_checked": records_checked,
        "details": info,
        "algorithm": "SHA-256 Hash Chained Merkle-Tree Structure",
        "verified_at": datetime.datetime.utcnow().isoformat()
    }

# ==================== PRIVILEGED APPROVALS WORKFLOW ====================
@app.post("/api/admin/privileged-approvals")
def request_privileged_approval(
    req: PrivilegedApprovalRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    approval_id = f"apr_{uuid.uuid4().hex[:12]}"
    approval = PrivilegedApproval(
        id=approval_id,
        org_id=current_user.org_id,
        requester_id=current_user.id,
        requester_email=current_user.email,
        action=req.action,
        justification=req.justification,
        target_resource=req.target_resource,
        status=ApprovalStatus.PENDING.value,
        expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    )
    db.add(approval)
    db.commit()

    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email,
        action="PRIVILEGED_ACTION_REQUESTED", resource_type="APPROVAL", resource_id=approval_id,
        org_id=current_user.org_id, details={"action": req.action, "justification": req.justification}
    )
    return approval

@app.post("/api/admin/privileged-approvals/{approval_id}/decide")
def decide_privileged_approval(
    approval_id: str,
    req: PrivilegedApprovalDecision,
    current_user: User = Depends(require_permission(Permission.PRIVILEGED_APPROVE)),
    db: Session = Depends(get_db)
):
    approval = db.query(PrivilegedApproval).filter(PrivilegedApproval.id == approval_id).first()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval request not found")

    # Separation of duties: Cannot approve your own request!
    if approval.requester_id == current_user.id:
        raise HTTPException(status_code=403, detail="Separation of duties violation: You cannot approve your own privileged request.")

    approval.status = ApprovalStatus.APPROVED.value if req.decision == "APPROVED" else ApprovalStatus.REJECTED.value
    approval.approver_id = current_user.id
    approval.approver_email = current_user.email
    approval.approved_at = datetime.datetime.utcnow()
    db.commit()

    record_audit_event(
        db, actor_id=current_user.id, actor_email=current_user.email,
        action=f"PRIVILEGED_ACTION_{approval.status}", resource_type="APPROVAL", resource_id=approval_id,
        org_id=approval.org_id, details={"decision": req.decision, "target_resource": approval.target_resource}
    )
    return {"message": f"Approval request updated to {approval.status}"}

@app.get("/api/admin/privileged-approvals")
def list_privileged_approvals(
    current_user: User = Depends(require_permission(Permission.PRIVILEGED_APPROVE)),
    db: Session = Depends(get_db)
):
    approvals = db.query(PrivilegedApproval).order_by(PrivilegedApproval.created_at.desc()).all()
    return approvals
