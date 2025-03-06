import json
from core.alert import Alert, InvestigationResult, ResponseAction
from core.llm import LLMClient, MockLLMClient

RESPONSE_PROMPT = """You are a security incident responder. Given an investigated alert, recommend and plan response actions. Return JSON with:

- actions: list of response actions, each with:
  - action: action identifier
  - target: what resource to act on
  - description: what the action does
  - priority: execution order (1 = first)
- notification: dict with escalate_to, severity, summary

Follow these principles:
1. Contain first, then eradicate, then recover
2. Preserve evidence before making changes
3. Minimize blast radius of response actions
4. Document everything for post-incident review"""


class ResponderAgent:

    def __init__(self, llm_client=None, use_mock=False, auto_respond=False):
        if use_mock:
            self.llm = MockLLMClient()
        else:
            self.llm = llm_client or LLMClient()
        self.auto_respond = auto_respond

    def plan_response(self, alert: Alert, investigation: InvestigationResult) -> list[ResponseAction]:
        prompt = self._build_prompt(alert, investigation)
        result = self.llm.analyze_json(RESPONSE_PROMPT, prompt)

        actions = []
        for i, action_data in enumerate(result.get("actions", [])):
            action = ResponseAction(
                action_id=f"{alert.alert_id}-resp-{i+1}",
                action_type=action_data.get("action", "unknown"),
                description=action_data.get("description", ""),
                target=action_data.get("target", ""),
                requires_approval=not self.auto_respond,
            )
            actions.append(action)

        return actions

    # TODO: execute_action via boto3
    # TODO: execute_playbook

    def _build_prompt(self, alert: Alert, investigation: InvestigationResult) -> str:
        return f"""Plan incident response for this alert:

Alert: {alert.title}
Severity: {alert.severity.value}

Investigation Findings:
{json.dumps(investigation.findings, indent=2)}

Risk Assessment: {investigation.risk_assessment}
Root Cause: {investigation.root_cause}
Affected Scope: {json.dumps(investigation.affected_scope)}

Recommendations from investigation:
{json.dumps(investigation.recommendations, indent=2)}

Plan the response actions as JSON."""
