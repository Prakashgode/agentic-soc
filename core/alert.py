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

    @classmethod
    def from_dict(cls, data: dict) -> "Alert":
        data = data.copy()
        if "severity" in data:
            data["severity"] = Severity(data["severity"])
        if "status" in data:
            data["status"] = AlertStatus(data["status"])
        return cls(**data)
