import datetime
import uuid
from backend.database import SessionLocal, init_db
from backend.models import Organization, User, UserRole, CloudAccount, SecurityEvent, ThreatAlert, AlertSeverity, AlertStatus
from backend.auth import get_password_hash
from backend.audit import record_audit_event

def seed_database():
    init_db()
    db = SessionLocal()
    try:
        # Check if already seeded
        if db.query(Organization).first():
            print("Database already contains data.")
            return

        print("Seeding organizations...")
        org1 = Organization(
            id="org_alpha_defense",
            name="Alpha Defense Corp",
            retention_days=90,
            security_policy={"mfa_required": True, "ip_allowlist": ["*"]}
        )
        org2 = Organization(
            id="org_beta_cloud",
            name="Beta Cloud Logistics",
            retention_days=180,
            security_policy={"mfa_required": False}
        )
        db.add_all([org1, org2])
        db.commit()

        print("Seeding users...")
        # 1. Super Admin
        super_admin = User(
            id="usr_superadmin",
            org_id=None,
            email="superadmin@citadel.sec",
            full_name="Chief SecOps (Super Admin)",
            hashed_password=get_password_hash("Citadel#Admin2026!"),
            role=UserRole.PLATFORM_SUPER_ADMIN.value,
            is_active=True,
            mfa_enabled=False
        )

        # 2. Org Admin (Alpha)
        org_admin = User(
            id="usr_orgadmin_alpha",
            org_id=org1.id,
            email="admin@alpha.sec",
            full_name="Sarah Connor (Alpha Admin)",
            hashed_password=get_password_hash("Alpha#Admin2026!"),
            role=UserRole.ORG_ADMIN.value,
            is_active=True,
            mfa_enabled=False
        )

        # 3. Security Analyst (Alpha)
        analyst = User(
            id="usr_analyst_alpha",
            org_id=org1.id,
            email="analyst@alpha.sec",
            full_name="Alex Mercer (SOC Lead Analyst)",
            hashed_password=get_password_hash("Analyst#Sec2026!"),
            role=UserRole.SECURITY_ANALYST.value,
            is_active=True,
            mfa_enabled=False
        )

        # 4. Auditor (Alpha)
        auditor = User(
            id="usr_auditor_alpha",
            org_id=org1.id,
            email="auditor@alpha.sec",
            full_name="Helen Vance (Compliance Auditor)",
            hashed_password=get_password_hash("Auditor#Check2026!"),
            role=UserRole.AUDITOR.value,
            is_active=True,
            mfa_enabled=False
        )

        db.add_all([super_admin, org_admin, analyst, auditor])
        db.commit()

        # Record Initial Tamper-Evident Audit Chains
        record_audit_event(
            db, actor_id=super_admin.id, actor_email=super_admin.email,
            action="SYSTEM_INITIALIZATION", resource_type="PLATFORM", resource_id="citadel_core",
            details={"version": "2.0.0", "status": "SECURE_BOOTSTRAP"}
        )

        # Seed Sample Cloud Events for Alpha Corp
        sample_events = [
            SecurityEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                org_id=org1.id,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=45),
                event_name="ConsoleLogin",
                event_source="signin.amazonaws.com",
                aws_region="us-east-1",
                source_ip="198.51.100.24",
                user_identity={"type": "IAMUser", "userName": "dev_deployer"},
                user_agent="AWS Console / Chrome",
                anomaly_score=0.15,
                is_anomalous=False,
                raw_payload={"eventSource": "signin.amazonaws.com", "responseElements": {"ConsoleLogin": "Success"}}
            ),
            SecurityEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                org_id=org1.id,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=30),
                event_name="CreateAccessKey",
                event_source="iam.amazonaws.com",
                aws_region="us-east-1",
                source_ip="203.0.113.88",
                user_identity={"type": "IAMUser", "userName": "attacker_shadow"},
                user_agent="aws-sdk-go/v1.38",
                anomaly_score=0.88,
                is_anomalous=True,
                raw_payload={"userName": "attacker_shadow", "eventName": "CreateAccessKey"}
            ),
            SecurityEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                org_id=org1.id,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=28),
                event_name="AttachUserPolicy",
                event_source="iam.amazonaws.com",
                aws_region="us-east-1",
                source_ip="203.0.113.88",
                user_identity={"type": "IAMUser", "userName": "attacker_shadow"},
                user_agent="aws-sdk-go/v1.38",
                anomaly_score=0.92,
                is_anomalous=True,
                raw_payload={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ),
            SecurityEvent(
                id=f"evt_{uuid.uuid4().hex[:12]}",
                org_id=org1.id,
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(minutes=15),
                event_name="StopLogging",
                event_source="cloudtrail.amazonaws.com",
                aws_region="us-east-1",
                source_ip="203.0.113.88",
                user_identity={"type": "IAMUser", "userName": "attacker_shadow"},
                user_agent="aws-sdk-go/v1.38",
                anomaly_score=0.98,
                is_anomalous=True,
                raw_payload={"name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-trail"}
            )
        ]
        db.add_all(sample_events)
        db.commit()

        # Seed Alert corresponding to the sequence
        alert = ThreatAlert(
            id=f"alt_{uuid.uuid4().hex[:12]}",
            org_id=org1.id,
            title="Defense Evasion: CloudTrail Logging Stopped by attacker_shadow",
            severity=AlertSeverity.CRITICAL.value,
            status=AlertStatus.NEW.value,
            anomaly_score=0.98,
            detection_type="BEHAVIORAL_SEQUENCE",
            explanation="Attacker attacker_shadow executed StopLogging after generating access keys and attaching AdministratorAccess policies.",
            evidence={"event_count": 3, "actor": "attacker_shadow", "source_ip": "203.0.113.88"},
            ai_remediation_plan={
                "summary": "AI Autonomous Remediation Strategy for attacker_shadow",
                "recommended_actions": [
                    "1. Immediately re-enable CloudTrail logging for trail 'arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-trail'.",
                    "2. Rotate and revoke temporary access session credentials for actor 'attacker_shadow'.",
                    "3. Apply SCP denying CloudTrail modification without break-glass privilege."
                ],
                "containment_commands": [
                    "aws cloudtrail start-logging --name arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-trail",
                    "aws iam put-user-policy --user-name attacker_shadow --policy-name IncidentContainmentDenyAll --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}'"
                ],
                "risk_level": "CRITICAL",
                "requires_human_approval": True,
                "status": "AWAITING_ANALYST_CONFIRMATION"
            },
            remediation_status="PENDING_APPROVAL",
            correlated_events_count=3
        )
        db.add(alert)
        db.commit()

        print("Database seed completed successfully.")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
