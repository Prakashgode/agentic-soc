import json
from core.alert import Alert, InvestigationResult, TriageResult

INVESTIGATION_PROMPT = """You are a senior threat investigator. Given a triaged security alert, perform a deep investigation and return JSON with:

- findings: list of key findings
- enriched_iocs: list of IOCs with reputation data
- timeline: chronological list of events
- risk_assessment: overall risk summary
- root_cause: identified root cause
- affected_scope: list of affected resources/accounts
- recommendations: list of remediation steps

Focus on:
1. Building an attack timeline
2. Identifying the full blast radius
3. IOC enrichment and correlation
4. Root cause analysis
5. Containment recommendations"""


class InvestigatorAgent:

    def __init__(self, llm_client=None, use_mock=False):
        if use_mock:
            from core.llm import MockLLMClient
            self.llm = MockLLMClient()
        else:
            from core.llm import LLMClient
            self.llm = llm_client or LLMClient()

    def investigate(self, alert: Alert, triage: TriageResult) -> InvestigationResult:
        prompt = self._build_prompt(alert, triage)
        result = self.llm.analyze_json(INVESTIGATION_PROMPT, prompt)

        return InvestigationResult(
            alert_id=alert.alert_id,
            findings=result.get("findings", []),
            enriched_iocs=result.get("enriched_iocs", []),
            timeline=result.get("timeline", []),
            risk_assessment=result.get("risk_assessment", ""),
            root_cause=result.get("root_cause", ""),
            affected_scope=result.get("affected_scope", []),
            recommendations=result.get("recommendations", []),
        )

    # TODO: enrich_iocs via VirusTotal/AbuseIPDB

    def _build_prompt(self, alert: Alert, triage: TriageResult) -> str:
        return f"""Investigate this triaged security alert:

Alert ID: {alert.alert_id}
Title: {alert.title}
Source: {alert.source}
Description: {alert.description}
Timestamp: {alert.timestamp}

Triage Assessment:
- Severity: {triage.assigned_severity.value} (score: {triage.severity_score})
- False Positive: {triage.is_false_positive}
- Reasoning: {triage.reasoning}

IOCs: {json.dumps(alert.iocs)}
Affected Resources: {json.dumps(alert.affected_resources)}
MITRE Tactics: {json.dumps(alert.mitre_tactics)}

Raw Data:
{json.dumps(alert.raw_data, indent=2)}

Provide your investigation findings as JSON."""
