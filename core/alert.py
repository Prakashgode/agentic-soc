from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    RESPONDED = "responded"
    CLOSED = "closed"


@dataclass
class Alert:
    alert_id: str
    title: str
    description: str
    source: str
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.NEW
    timestamp: str = ""
    raw_data: dict = field(default_factory=dict)
    iocs: list = field(default_factory=list)
    mitre_tactics: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    affected_resources: list = field(default_factory=list)
    region: str = ""
    account_id: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "severity": self.severity.value,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "iocs": self.iocs,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "affected_resources": self.affected_resources,
            "region": self.region,
            "account_id": self.account_id,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        data = data.copy()
        # coerce string values to enums
        if "severity" in data:
            data["severity"] = Severity(data["severity"])
        if "status" in data:
            data["status"] = AlertStatus(data["status"])
        return cls(**data)


@dataclass
class TriageResult:
    alert_id: str
    severity_score: int
    assigned_severity: Severity
    is_false_positive: bool
    confidence: float
    reasoning: str
    recommended_actions: list = field(default_factory=list)
    mitre_mapping: dict = field(default_factory=dict)


@dataclass
class InvestigationResult:
    alert_id: str
    findings: list = field(default_factory=list)
    enriched_iocs: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    risk_assessment: str = ""
    root_cause: str = ""
    affected_scope: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)


@dataclass
class ResponseAction:
    action_id: str
    action_type: str
    description: str
    target: str
    status: str = "pending"
    requires_approval: bool = True
    executed_at: Optional[str] = None
    result: str = ""
