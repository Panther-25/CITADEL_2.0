import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Any, Tuple
from datetime import datetime

# Suspicious API Call Heuristic Weights
SENSITIVE_ACTIONS = {
    "ConsoleLogin": 0.3,
    "CreateUser": 0.8,
    "AttachUserPolicy": 0.85,
    "AttachRolePolicy": 0.85,
    "CreateAccessKey": 0.8,
    "DeleteTrail": 0.95,
    "StopLogging": 0.95,
    "PutBucketPolicy": 0.75,
    "AuthorizeSecurityGroupIngress": 0.75,
    "ModifySecurityGroupRules": 0.75,
    "GetSecretValue": 0.7,
    "BatchGetSecretValue": 0.85,
    "AssumeRole": 0.5,
    "CreateKeyPair": 0.6
}

def extract_event_features(events: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, List[str]]:
    """
    Extracts numerical features from CloudTrail events for Isolation Forest anomaly scoring.
    Features:
    1. is_sensitive_action (float)
    2. is_error (0 or 1)
    3. hour_of_day (0-23 normalized)
    4. is_off_hours (1 if between 22:00 and 06:00, else 0)
    5. has_root_identity (1 if root, else 0)
    """
    rows = []
    event_ids = []

    for ev in events:
        eid = ev.get("id") or str(ev.get("eventID", ""))
        event_ids.append(eid)

        name = ev.get("event_name") or ev.get("eventName", "")
        error = 1.0 if (ev.get("error_code") or ev.get("errorCode")) else 0.0
        
        # Identity
        identity = ev.get("user_identity") or ev.get("userIdentity", {})
        is_root = 1.0 if isinstance(identity, dict) and identity.get("type") == "Root" else 0.0

        # Time
        raw_ts = ev.get("timestamp") or ev.get("eventTime")
        if isinstance(raw_ts, str):
            try:
                dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.utcnow()
        elif isinstance(raw_ts, datetime):
            dt = raw_ts
        else:
            dt = datetime.utcnow()

        hour = dt.hour
        is_off_hours = 1.0 if (hour >= 22 or hour <= 6) else 0.0
        sensitive_weight = SENSITIVE_ACTIONS.get(name, 0.1)

        rows.append({
            "sensitive_weight": sensitive_weight,
            "is_error": error,
            "hour_norm": hour / 24.0,
            "is_off_hours": is_off_hours,
            "is_root": is_root
        })

    df = pd.DataFrame(rows)
    return df, event_ids

class CloudThreatEngine:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42
        )
        self.is_fitted = False

    def fit_and_score(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Fits Isolation Forest on events and computes calibrated anomaly and risk scores.
        """
        if not events:
            return []

        df, event_ids = extract_event_features(events)
        
        # When dataset is very small, use heuristic baseline
        if len(df) < 5:
            scored_results = []
            for idx, row in df.iterrows():
                heuristic_score = min(1.0, row["sensitive_weight"] * 0.7 + row["is_error"] * 0.2 + row["is_root"] * 0.3)
                is_anomaly = heuristic_score >= 0.65
                scored_results.append({
                    "event_id": event_ids[idx],
                    "anomaly_score": round(float(heuristic_score), 4),
                    "is_anomalous": is_anomaly,
                    "explanation": self.generate_explanation(events[idx], heuristic_score, is_anomaly)
                })
            return scored_results

        # Train Isolation Forest
        self.model.fit(df)
        self.is_fitted = True

        # raw anomaly score: lower means more anomalous. Invert & scale to [0, 1]
        raw_scores = self.model.decision_function(df)
        # Normalization
        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s > min_s:
            normalized_scores = 1.0 - (raw_scores - min_s) / (max_s - min_s)
        else:
            normalized_scores = np.zeros(len(raw_scores))

        predictions = self.model.predict(df) # -1 for outlier, 1 for inlier

        results = []
        for i, pred in enumerate(predictions):
            anomaly_score = float(normalized_scores[i])
            is_anomaly = (pred == -1) or (anomaly_score >= 0.7)
            event_obj = events[i]

            results.append({
                "event_id": event_ids[i],
                "anomaly_score": round(anomaly_score, 4),
                "is_anomalous": bool(is_anomaly),
                "explanation": self.generate_explanation(event_obj, anomaly_score, is_anomaly)
            })

        return results

    def detect_sequence_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detects multi-step attack sequences (e.g., Recon -> Privilege Escalation -> Defense Evasion -> Exfiltration).
        """
        alerts = []
        sorted_events = sorted(events, key=lambda x: str(x.get("timestamp") or x.get("eventTime", "")))

        # Group by actor or source IP
        actor_groups: Dict[str, List[Dict[str, Any]]] = {}
        for ev in sorted_events:
            identity = ev.get("user_identity") or ev.get("userIdentity", {})
            actor = identity.get("userName") or identity.get("arn") or ev.get("source_ip") or "unknown"
            actor_groups.setdefault(actor, []).append(ev)

        for actor, ev_list in actor_groups.items():
            action_names = [e.get("event_name") or e.get("eventName", "") for e in ev_list]
            
            # Pattern 1: Disabling CloudTrail Defense Evasion
            if any(a in ["StopLogging", "DeleteTrail", "UpdateTrail"] for a in action_names):
                alerts.append({
                    "title": f"Defense Evasion: CloudTrail Logging Tampered by {actor}",
                    "severity": "CRITICAL",
                    "detection_type": "BEHAVIORAL_SEQUENCE",
                    "explanation": f"Actor '{actor}' attempted to stop or delete CloudTrail monitoring, an indicator of defense evasion.",
                    "evidence": [e.get("id") or str(e.get("eventID")) for e in ev_list if (e.get("event_name") or e.get("eventName")) in ["StopLogging", "DeleteTrail", "UpdateTrail"]],
                    "anomaly_score": 0.98
                })

            # Pattern 2: Privilege Escalation chain
            if any(a in ["CreateUser", "CreateAccessKey"] for a in action_names) and any(a in ["AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy"] for a in action_names):
                alerts.append({
                    "title": f"Privilege Escalation Sequence Detected for {actor}",
                    "severity": "HIGH",
                    "detection_type": "BEHAVIORAL_SEQUENCE",
                    "explanation": f"Actor '{actor}' created an IAM credential and immediately attached administrative privileges.",
                    "evidence": [e.get("id") or str(e.get("eventID")) for e in ev_list],
                    "anomaly_score": 0.89
                })

            # Pattern 3: Brute force / Credential Spraying
            consecutive_errors = sum(1 for e in ev_list if (e.get("error_code") or e.get("errorCode")) in ["AccessDenied", "UnauthorizedOperation"])
            if consecutive_errors >= 3:
                alerts.append({
                    "title": f"Repeated Authorization Failures / Reconnaissance by {actor}",
                    "severity": "MEDIUM",
                    "detection_type": "RULE_BASED",
                    "explanation": f"Actor generated {consecutive_errors} consecutive permission errors, indicating unauthorized discovery or credential spraying.",
                    "evidence": [e.get("id") or str(e.get("eventID")) for e in ev_list if e.get("error_code")],
                    "anomaly_score": 0.74
                })

        return alerts

    def generate_remediation_plan(self, title: str, detection_type: str, actor: str, event_names: List[str]) -> Dict[str, Any]:
        """
        Synthesizes an automated, cloud-native remediation fix tailored to the specific threat.
        Enforces human-in-the-loop: provides dry-run command, risk analysis, and containment actions.
        """
        actions = []
        containment_commands = []
        risk_level = "HIGH"

        if "Defense Evasion" in title or any(a in ["StopLogging", "DeleteTrail"] for a in event_names):
            actions = [
                f"1. Immediately re-enable CloudTrail logging for affected trail arn.",
                f"2. Rotate and revoke temporary access session credentials for actor '{actor}'.",
                f"3. Apply SCP (Service Control Policy) denying CloudTrail modification without break-glass privilege."
            ]
            containment_commands = [
                f"aws cloudtrail start-logging --name arn:aws:cloudtrail:us-east-1:123456789012:trail/corp-trail",
                f"aws iam put-user-policy --user-name {actor} --policy-name IncidentContainmentDenyAll --policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'"
            ]
            risk_level = "CRITICAL"

        elif "Privilege Escalation" in title or any(a in ["AttachUserPolicy", "AttachRolePolicy"] for a in event_names):
            actions = [
                f"1. Detach unapproved policy 'AdministratorAccess' from actor '{actor}'.",
                f"2. Inactivate recent access keys generated within the last 1 hour.",
                f"3. Force password reset and MFA challenge on next console login."
            ]
            containment_commands = [
                f"aws iam detach-user-policy --user-name {actor} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                f"aws iam update-access-key --user-name {actor} --access-key-id <GENERATED_KEY_ID> --status Inactive"
            ]
            risk_level = "HIGH"

        else:
            actions = [
                f"1. Temporarily isolate source IP associated with anomalous requests.",
                f"2. Initiate step-up MFA verification for principal '{actor}'."
            ]
            containment_commands = [
                f"aws wafv2 update-ip-set --name CitadelQuarantineList --scope REGIONAL --addresses <SOURCE_IP>/32"
            ]
            risk_level = "MEDIUM"

        return {
            "summary": f"AI Autonomous Remediation Strategy for {actor or 'target principal'}",
            "recommended_actions": actions,
            "containment_commands": containment_commands,
            "risk_level": risk_level,
            "requires_human_approval": True,
            "status": "AWAITING_ANALYST_CONFIRMATION"
        }

    def generate_explanation(self, event: Dict[str, Any], score: float, is_anomalous: bool) -> str:
        name = event.get("event_name") or event.get("eventName", "Unknown")
        actor = (event.get("user_identity") or {}).get("userName", "UnknownActor")
        error = event.get("error_code") or event.get("errorCode")

        reasons = []
        if name in SENSITIVE_ACTIONS:
            reasons.append(f"High-impact API operation '{name}'")
        if error:
            reasons.append(f"Operation failed with error '{error}'")
        if score >= 0.7:
            reasons.append(f"Statistically divergent behavioral pattern (Isolation Forest Score: {score:.2f})")

        if not reasons:
            return f"Routine cloud operation '{name}' executed by '{actor}' within expected baseline."

        return f"Flagged as {'ANOMALOUS' if is_anomalous else 'SUSPICIOUS'}: " + "; ".join(reasons) + "."
