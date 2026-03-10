"""Tests for the agentic-soc pipeline using mock LLM (no API keys needed)."""

import json
import os
import sys

# ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.alert import Alert, Severity, AlertStatus, TriageResult, InvestigationResult, ResponseAction
from core.llm import MockLLMClient
from agents.triage_agent import TriageAgent
from agents.investigator_agent import InvestigatorAgent
from agents.responder_agent import ResponderAgent


SAMPLE_ALERTS_PATH = os.path.join(os.path.dirname(__file__), "..", "samples", "sample_alerts.json")


def _load_sample_alerts():
    with open(SAMPLE_ALERTS_PATH) as f:
        data = json.load(f)
    return [Alert.from_dict(a) for a in data]


# ---------- core/alert.py ----------

class TestAlertModel:
    def test_alert_from_dict(self):
        raw = {
            "alert_id": "TEST-001",
            "title": "Test Alert",
            "description": "Unit test alert",
            "source": "test",
            "severity": "high",
        }
        alert = Alert.from_dict(raw)
        assert alert.alert_id == "TEST-001"
        assert alert.severity == Severity.HIGH

    def test_alert_round_trip(self):
        alert = Alert(
            alert_id="RT-001",
            title="Round Trip",
            description="test",
            source="unit",
            severity=Severity.CRITICAL,
        )
        d = alert.to_dict()
        restored = Alert.from_dict(d)
        assert restored.alert_id == alert.alert_id
        assert restored.severity == Severity.CRITICAL

    def test_severity_enum_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_load_sample_alerts(self):
        alerts = _load_sample_alerts()
        assert len(alerts) == 4
        ids = {a.alert_id for a in alerts}
        assert "CT-2024-001" in ids
        assert "GD-2024-002" in ids


# ---------- core/llm.py ----------

class TestMockLLM:
    def test_mock_client_no_api_key(self):
        client = MockLLMClient()
        assert client.model == "mock"

    def test_mock_triage_response(self):
        client = MockLLMClient()
        result = client.analyze_json("triage this alert", "some alert data")
        assert "severity_score" in result
        assert "severity" in result
        assert result["is_false_positive"] is False

    def test_mock_investigation_response(self):
        client = MockLLMClient()
        result = client.analyze_json("You are a senior threat investigator. Perform a deep investigation", "some data")
        assert "findings" in result
        assert "timeline" in result
        assert len(result["findings"]) > 0

    def test_mock_response_plan(self):
        client = MockLLMClient()
        result = client.analyze_json("You are a security incident responder. Plan response actions", "some data")
        assert "actions" in result
        assert len(result["actions"]) > 0


# ---------- agents ----------

class TestTriageAgent:
    def test_triage_single_alert(self):
        agent = TriageAgent(use_mock=True)
        alerts = _load_sample_alerts()
        result = agent.triage(alerts[0])
        assert isinstance(result, TriageResult)
        assert result.alert_id == "CT-2024-001"
        assert result.severity_score > 0
        assert isinstance(result.assigned_severity, Severity)

    def test_batch_triage(self):
        agent = TriageAgent(use_mock=True)
        alerts = _load_sample_alerts()
        results = agent.batch_triage(alerts)
        assert len(results) == 4
        # results should be sorted by severity_score descending
        scores = [r.severity_score for r in results]
        assert scores == sorted(scores, reverse=True)


class TestInvestigatorAgent:
    def test_investigate_alert(self):
        triage_agent = TriageAgent(use_mock=True)
        investigator = InvestigatorAgent(use_mock=True)
        alerts = _load_sample_alerts()
        triage_result = triage_agent.triage(alerts[0])
        investigation = investigator.investigate(alerts[0], triage_result)
        assert isinstance(investigation, InvestigationResult)
        assert investigation.alert_id == "CT-2024-001"
        assert len(investigation.findings) > 0
        assert len(investigation.timeline) > 0


class TestResponderAgent:
    def test_plan_response(self):
        triage_agent = TriageAgent(use_mock=True)
        investigator = InvestigatorAgent(use_mock=True)
        responder = ResponderAgent(use_mock=True)
        alerts = _load_sample_alerts()
        triage_result = triage_agent.triage(alerts[0])
        investigation = investigator.investigate(alerts[0], triage_result)
        actions = responder.plan_response(alerts[0], investigation)
        assert len(actions) > 0
        assert all(isinstance(a, ResponseAction) for a in actions)
        assert all(a.action_type for a in actions)


# ---------- full pipeline ----------

class TestFullPipeline:
    def test_end_to_end_mock(self):
        """Run the full triage -> investigate -> respond pipeline in mock mode."""
        alerts = _load_sample_alerts()
        triage_agent = TriageAgent(use_mock=True)
        investigator = InvestigatorAgent(use_mock=True)
        responder = ResponderAgent(use_mock=True)

        triage_results = triage_agent.batch_triage(alerts)
        assert len(triage_results) == len(alerts)

        high_alerts = [
            (a, t)
            for a, t in zip(alerts, triage_results)
            if t.assigned_severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        # mock always returns high, so we should get results
        assert len(high_alerts) > 0

        for alert, triage_result in high_alerts:
            investigation = investigator.investigate(alert, triage_result)
            assert investigation.alert_id == alert.alert_id
            actions = responder.plan_response(alert, investigation)
            assert len(actions) > 0
