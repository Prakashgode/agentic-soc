![CI](https://github.com/Prakashgode/agentic-soc/actions/workflows/ci.yml/badge.svg)

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

## Sample Output

```
$ python main.py pipeline --input samples/sample_alerts.json --mock

Loading 4 alerts from samples/sample_alerts.json...

[TRIAGE] Alert: UnauthorizedAccess:IAMUser/ConsoleLogin
         Severity: HIGH (score: 8.2)
         → Forwarding to investigation

[TRIAGE] Alert: S3:BucketPolicyChanged/PublicAccess
         Severity: CRITICAL (score: 9.5)
         → Forwarding to investigation

[TRIAGE] Alert: SSH:BruteForce/SuccessfulLogin
         Severity: HIGH (score: 7.8)
         → Forwarding to investigation

[TRIAGE] Alert: EC2:SecurityGroupOpened/AllTraffic
         Severity: MEDIUM (score: 5.4)
         → Queued for review

[INVESTIGATE] Building timeline for alert CT-2024-001...
         - 2024-01-15 08:23: Console login from 198.51.100.23 (unusual geo)
         - 2024-01-15 08:24: IAM policy attachment (AdministratorAccess)
         - 2024-01-15 08:25: CreateAccessKey for svc-backup-admin
         → Possible account compromise

[INVESTIGATE] Building timeline for alert GD-2024-002...
         - 2024-01-15 10:45: PutBucketPolicy on prod-customer-data
         - 2024-01-15 10:45: Principal set to * (public read)
         → S3 data exposure confirmed

[RESPOND] Matched playbook: compromised_iam_credentials
         Action: Disable IAM access keys (dry-run)
         Action: Revoke active sessions (dry-run)
         Action: Block source IP 198.51.100.23 (dry-run)

[RESPOND] Matched playbook: s3_public_exposure
         Action: Revert bucket policy (dry-run)
         Action: Enable S3 Block Public Access (dry-run)

Pipeline complete: 4 alerts processed, 2 high severity, 1 critical
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


