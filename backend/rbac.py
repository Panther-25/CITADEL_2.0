from typing import Set, Dict
from backend.models import UserRole

# Define atomic platform permissions
class Permission:
    # Organization and Tenancy
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    ORG_CREATE = "org:create"

    # User Management
    USER_READ = "user:read"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_ROLE_ASSIGN = "user:role_assign"

    # Security & Audit Policies
    SECURITY_POLICY_READ = "security:policy_read"
    SECURITY_POLICY_UPDATE = "security:policy_update"
    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    PRIVILEGED_APPROVE = "privileged:approve"

    # Cloud Accounts & Integrations
    CLOUD_READ = "cloud:read"
    CLOUD_MANAGE = "cloud:manage"

    # Security Events & Ingestion
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"
    EVENTS_EXPORT = "events:export"

    # Detections & AI Models
    ALERTS_READ = "alerts:read"
    ALERTS_MANAGE = "alerts:manage"
    INVESTIGATE = "investigate:manage"
    MODEL_READ = "model:read"
    MODEL_TRAIN = "model:train"
    MODEL_DEPLOY = "model:deploy"

# Server-enforced role to permission matrix
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    UserRole.PLATFORM_SUPER_ADMIN.value: {
        Permission.ORG_READ, Permission.ORG_UPDATE, Permission.ORG_DELETE, Permission.ORG_CREATE,
        Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE, Permission.USER_ROLE_ASSIGN,
        Permission.SECURITY_POLICY_READ, Permission.SECURITY_POLICY_UPDATE,
        Permission.AUDIT_READ, Permission.AUDIT_VERIFY, Permission.PRIVILEGED_APPROVE,
        Permission.CLOUD_READ, Permission.CLOUD_MANAGE,
        Permission.EVENTS_READ, Permission.EVENTS_INGEST, Permission.EVENTS_EXPORT,
        Permission.ALERTS_READ, Permission.ALERTS_MANAGE, Permission.INVESTIGATE,
        Permission.MODEL_READ, Permission.MODEL_TRAIN, Permission.MODEL_DEPLOY
    },
    UserRole.SECURITY_ADMIN.value: {
        Permission.ORG_READ,
        Permission.USER_READ,
        Permission.SECURITY_POLICY_READ, Permission.SECURITY_POLICY_UPDATE,
        Permission.AUDIT_READ, Permission.AUDIT_VERIFY,
        Permission.CLOUD_READ, Permission.CLOUD_MANAGE,
        Permission.EVENTS_READ, Permission.EVENTS_INGEST, Permission.EVENTS_EXPORT,
        Permission.ALERTS_READ, Permission.ALERTS_MANAGE, Permission.INVESTIGATE,
        Permission.MODEL_READ, Permission.MODEL_TRAIN, Permission.MODEL_DEPLOY
    },
    UserRole.ORG_ADMIN.value: {
        Permission.ORG_READ, Permission.ORG_UPDATE,
        Permission.USER_READ, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE,
        Permission.SECURITY_POLICY_READ,
        Permission.AUDIT_READ,
        Permission.CLOUD_READ, Permission.CLOUD_MANAGE,
        Permission.EVENTS_READ, Permission.EVENTS_INGEST, Permission.EVENTS_EXPORT,
        Permission.ALERTS_READ, Permission.INVESTIGATE,
        Permission.MODEL_READ
    },
    UserRole.SECURITY_ANALYST.value: {
        Permission.ORG_READ,
        Permission.USER_READ,
        Permission.AUDIT_READ,
        Permission.CLOUD_READ,
        Permission.EVENTS_READ, Permission.EVENTS_INGEST, Permission.EVENTS_EXPORT,
        Permission.ALERTS_READ, Permission.ALERTS_MANAGE, Permission.INVESTIGATE,
        Permission.MODEL_READ
    },
    UserRole.AUDITOR.value: {
        Permission.ORG_READ,
        Permission.USER_READ,
        Permission.SECURITY_POLICY_READ,
        Permission.AUDIT_READ, Permission.AUDIT_VERIFY,
        Permission.CLOUD_READ,
        Permission.EVENTS_READ,
        Permission.ALERTS_READ,
        Permission.MODEL_READ
    },
    UserRole.VIEWER.value: {
        Permission.ORG_READ,
        Permission.EVENTS_READ,
        Permission.ALERTS_READ
    }
}

def has_permission(role: str, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms
