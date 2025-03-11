# Agentic SOC

SOC pipeline that runs triage, investigation, and response on cloud security alerts using an LLM. Pulls from CloudTrail, GuardDuty, and Sentinel.

**Status: Active Development**

## Architecture

```
                    ┌─────────────────────┐
                    │   Alert Sources      │
                    │ CloudTrail | GuardDuty│
                    │ Sentinel | Custom    │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │   Triage Agent       │
                    │ - Severity scoring   │
                    │ - FP detection       │
                    │ - MITRE ATT&CK map  │
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │ Investigator Agent   │
                    │ - IOC enrichment     │
                    │ - Timeline building  │
                    │ - Root cause analysis│
                    └─────────┬───────────┘
                              │
                    ┌─────────▼───────────┐
                    │  Responder Agent     │
                    │ - Playbook execution │
                    │ - Containment actions│
                    │ - Escalation         │
                    └─────────────────────┘
```

## Quick Start

```bash
pip install -r requirements.txt

# mock mode, no API key needed
python main.py triage --mock
python main.py investigate --alert-id CT-2024-001 --mock
python main.py respond --alert-id CT-2024-001 --mock
python main.py pipeline --mock
```

## With a real LLM

```bash
export OPENAI_API_KEY="your-key"
python main.py pipeline
```

## Sample Alerts

| Alert ID | Type | Source | Severity |
|----------|------|--------|----------|
| CT-2024-001 | Unauthorized IAM User Creation | CloudTrail | High |
| GD-2024-002 | S3 Bucket Public Exposure | GuardDuty | Critical |
| SN-2024-003 | SSH Brute Force + Successful Login | Sentinel | High |
| CT-2024-004 | Security Group Opened to 0.0.0.0/0 | CloudTrail | Medium |

## Playbooks

- `iam_compromise.yaml` — IAM cred compromise
- `s3_exposure.yaml` — S3 public exposure

## Structure

```
agentic-soc/
├── agents/
│   ├── triage_agent.py
│   ├── investigator_agent.py
│   └── responder_agent.py
├── core/
│   ├── alert.py               # data models
│   └── llm.py                 # LLM client + mock
├── playbooks/
├── samples/
│   └── sample_alerts.json
├── config/
│   └── settings.yaml
├── main.py
└── requirements.txt
```

## TODO

- [ ] VirusTotal / AbuseIPDB IOC enrichment
- [ ] Live AWS remediation via boto3
- [ ] Slack/Teams webhook
- [ ] CloudTrail log correlation
- [ ] Multi-account support

## Stack

- Python 3.10+, OpenAI GPT-4, Click, Rich, PyYAML

## License

MIT
