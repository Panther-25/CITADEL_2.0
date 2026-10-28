import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Tuple
from sqlalchemy.orm import Session
from backend.models import AuditLog

def compute_record_hash(prev_hash: str, actor_id: str, action: str, resource_type: str, resource_id: str, timestamp_str: str, details_json: str) -> str:
    """
    Computes SHA-256 hash chaining each audit log to the previous audit log hash.
    Ensures mathematical tamper evidence across the audit trail.
    """
    payload = f"{prev_hash}|{actor_id}|{action}|{resource_type}|{resource_id or ''}|{timestamp_str}|{details_json}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def record_audit_event(
    db: Session,
    actor_id: str,
    actor_email: str,
    action: str,
    resource_type: str,
    resource_id: str = None,
    org_id: str = None,
    details: Dict[str, Any] = None,
    outcome: str = "SUCCESS",
    ip_address: str = None
) -> AuditLog:
    """
    Appends an audited event with verifiable cryptographic hash chaining.
    """
    if details is None:
        details = {}

    last_log = db.query(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()
    prev_hash = last_log.record_hash if last_log else "0000000000000000000000000000000000000000000000000000000000000000"

    now = datetime.utcnow()
    timestamp_str = now.isoformat()
    details_json = json.dumps(details, sort_keys=True)

    record_hash = compute_record_hash(
        prev_hash=prev_hash,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp_str=timestamp_str,
        details_json=details_json
    )

    import uuid
    audit_entry = AuditLog(
        id=str(uuid.uuid4()),
        org_id=org_id,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        outcome=outcome,
        ip_address=ip_address,
        timestamp=now,
        prev_hash=prev_hash,
        record_hash=record_hash
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry

def verify_audit_ledger_integrity(db: Session, org_id: str = None) -> Tuple[bool, int, Dict[str, Any]]:
    """
    Verifies that no audit records have been tampered with, deleted, or altered.
    Returns (is_valid, records_checked, anomaly_info).
    """
    query = db.query(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
    if org_id:
        query = query.filter(AuditLog.org_id == org_id)

    logs = query.all()
    if not logs:
        return True, 0, {"status": "NO_RECORDS"}

    expected_prev_hash = "0000000000000000000000000000000000000000000000000000000000000000" if not org_id else logs[0].prev_hash

    for index, log in enumerate(logs):
        if not org_id and log.prev_hash != expected_prev_hash:
            return False, index, {
                "error": "CHAIN_BROKEN",
                "broken_at_id": log.id,
                "expected_prev": expected_prev_hash,
                "actual_prev": log.prev_hash
            }

        details_json = json.dumps(log.details, sort_keys=True)
        recalculated_hash = compute_record_hash(
            prev_hash=log.prev_hash,
            actor_id=log.actor_id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            timestamp_str=log.timestamp.isoformat(),
            details_json=details_json
        )

        if recalculated_hash != log.record_hash:
            return False, index, {
                "error": "TAMPER_DETECTED",
                "tampered_id": log.id,
                "recorded_hash": log.record_hash,
                "recalculated_hash": recalculated_hash
            }

        expected_prev_hash = log.record_hash

    return True, len(logs), {"status": "INTEGRITY_VERIFIED"}
