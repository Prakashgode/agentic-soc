import json
import os
from typing import Optional

import yaml


def load_config() -> dict:
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "settings.yaml")
    with open(config_path) as f:
        return yaml.safe_load(f)


class LLMClient:

    def __init__(self, api_key: Optional[str] = None):
        self.config = load_config()
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = self.config["llm"]["model"]
        self.temperature = self.config["llm"]["temperature"]
        self.max_tokens = self.config["llm"]["max_tokens"]
        self._client = None

    @property
    def client(self):
        # lazy init so we don't require openai unless actually called
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)
        return self._client

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict:
        response = self.analyze(system_prompt, user_prompt)
        try:
            # strip any prose around the JSON blob
            start = response.index("{")
            end = response.rindex("}") + 1
            return json.loads(response[start:end])
        except (ValueError, json.JSONDecodeError):
            return {"raw_response": response, "parse_error": True}


class MockLLMClient(LLMClient):
    """No-API mock for local testing."""

    def __init__(self):
        self.config = load_config()
        self.model = "mock"

    def analyze(self, system_prompt: str, user_prompt: str) -> str:
        return self._generate_mock_response(user_prompt)

    def analyze_json(self, system_prompt: str, user_prompt: str) -> dict:
        if "triage" in system_prompt.lower():
            return self._mock_triage()
        if "investigat" in system_prompt.lower():
            return self._mock_investigation()
        if "respond" in system_prompt.lower() or "playbook" in system_prompt.lower():
            return self._mock_response()
        return {"analysis": "Mock analysis complete", "confidence": 0.85}

    def _mock_triage(self) -> dict:
        return {
            "severity_score": 85,
            "severity": "high",
            "is_false_positive": False,
            "confidence": 0.92,
            "reasoning": "Alert indicates unauthorized API calls from an unrecognized IP address "
            "targeting IAM resources. The source IP is not in any known allowlist and the "
            "actions attempted include privilege escalation patterns.",
            "recommended_actions": [
                "Block source IP at network level",
                "Review IAM access logs for the affected account",
                "Check for any newly created IAM users or roles",
                "Verify MFA status on all admin accounts",
            ],
            "mitre_mapping": {
                "tactics": ["Initial Access", "Privilege Escalation"],
                "techniques": ["T1078 - Valid Accounts", "T1098 - Account Manipulation"],
            },
        }

    def _mock_investigation(self) -> dict:
        return {
            "findings": [
                "Source IP 198.51.100.23 has been seen in 3 threat intelligence feeds",
                "5 failed API calls preceded the successful IAM:CreateUser call",
                "The created user was assigned AdministratorAccess policy",
                "Activity originated from a TOR exit node",
            ],
            "enriched_iocs": [
                {"type": "ip", "value": "198.51.100.23", "reputation": "malicious", "source": "AbuseIPDB"},
                {"type": "user-agent", "value": "python-requests/2.28.0", "reputation": "suspicious"},
            ],
            "timeline": [
                "2024-01-15T08:23:01Z - First failed iam:CreateUser attempt",
                "2024-01-15T08:23:15Z - 4 more failed attempts with different parameters",
                "2024-01-15T08:24:02Z - Successful iam:CreateUser (user: svc-backup-admin)",
                "2024-01-15T08:24:05Z - iam:AttachUserPolicy (AdministratorAccess)",
                "2024-01-15T08:25:30Z - iam:CreateAccessKey for new user",
            ],
            "risk_assessment": "HIGH - Unauthorized IAM user creation with admin privileges indicates "
            "active compromise. Immediate containment required.",
            "root_cause": "Compromised access key used from external IP to create backdoor admin account.",
            "affected_scope": [
                "AWS Account 123456789012",
                "IAM User: svc-backup-admin (newly created)",
                "Region: us-east-1",
            ],
            "recommendations": [
                "Immediately delete the unauthorized IAM user svc-backup-admin",
                "Rotate all access keys for the compromised principal",
                "Enable GuardDuty if not already active",
                "Review CloudTrail for additional unauthorized activity",
                "Implement SCP to restrict IAM user creation",
            ],
        }

    def _mock_response(self) -> dict:
        return {
            "actions": [
                {
                    "action": "isolate_iam_user",
                    "target": "svc-backup-admin",
                    "description": "Attach deny-all policy to unauthorized IAM user",
                    "priority": 1,
                },
                {
                    "action": "revoke_access_keys",
                    "target": "compromised-principal",
                    "description": "Deactivate all access keys for the compromised account",
                    "priority": 2,
                },
                {
                    "action": "block_ip",
                    "target": "198.51.100.23",
                    "description": "Add IP to NACL deny list and WAF blocklist",
                    "priority": 3,
                },
            ],
            "notification": {
                "escalate_to": "security-oncall",
                "severity": "high",
                "summary": "Active IAM compromise detected - backdoor admin account created",
            },
        }

    def _generate_mock_response(self, prompt: str) -> str:
        return json.dumps(self._mock_triage(), indent=2)
