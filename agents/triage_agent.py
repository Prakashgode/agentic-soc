import json
from core.alert import Alert, Severity, TriageResult
from core.llm import LLMClient, MockLLMClient

TRIAGE_SYSTEM_PROMPT = """You are an expert SOC analyst performing alert triage. Given a security alert, analyze it and return a JSON response with:

- severity_score (0-100): Numeric severity rating
- severity: critical/high/medium/low/info
- is_false_positive: boolean
- confidence: float 0-1
- reasoning: detailed explanation of your assessment
- recommended_actions: list of next steps
- mitre_mapping: dict with tactics and techniques arrays

Consider these factors:
1. Source reliability and context
2. MITRE ATT&CK mapping
3. Affected resource criticality
4. Historical patterns
5. IOC reputation"""


class TriageAgent:

    def __init__(self, llm_client=None, use_mock=False):
        if use_mock:
            self.llm = MockLLMClient()
        else:
            self.llm = llm_client or LLMClient()

    def triage(self, alert: Alert) -> TriageResult:
        prompt = self._build_prompt(alert)
        result = self.llm.analyze_json(TRIAGE_SYSTEM_PROMPT, prompt)

        severity = Severity(result.get("severity", "medium"))

        return TriageResult(
            alert_id=alert.alert_id,
            severity_score=result.get("severity_score", 50),
            assigned_severity=severity,
            is_false_positive=result.get("is_false_positive", False),
            confidence=result.get("confidence", 0.5),
            reasoning=result.get("reasoning", "No reasoning provided"),
            recommended_actions=result.get("recommended_actions", []),
            mitre_mapping=result.get("mitre_mapping", {}),
        )

    def batch_triage(self, alerts: list[Alert]) -> list[TriageResult]:
        results = [self.triage(alert) for alert in alerts]
        results.sort(key=lambda r: r.severity_score, reverse=True)
        return results

    def _build_prompt(self, alert: Alert) -> str:
        return f"""Analyze this security alert:

Alert ID: {alert.alert_id}
Title: {alert.title}
Source: {alert.source}
Description: {alert.description}
Timestamp: {alert.timestamp}
Region: {alert.region}
Account: {alert.account_id}
Affected Resources: {json.dumps(alert.affected_resources)}
IOCs: {json.dumps(alert.iocs)}

Raw Data:
{json.dumps(alert.raw_data, indent=2)}

Provide your triage assessment as JSON."""
