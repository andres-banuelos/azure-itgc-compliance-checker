# Azure ITGC Compliance Checker

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?logo=microsoftazure&logoColor=white)
![NIST CSF](https://img.shields.io/badge/NIST%20CSF-2.0-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> A Python CLI tool that automates foundational Azure ITGC control checks and maps findings to NIST CSF 2.0 — built from first-hand Big 4 SOX audit experience.

---

## What This Tool Does

IT General Controls (ITGCs) are the backbone of SOX compliance and cloud security audits. Traditionally, auditors collect evidence manually: screenshots, portal exports, and walkthroughs. This tool **automates that evidence collection** for a curated set of Azure controls, producing a structured findings report that a security team or auditor can act on immediately.

It is designed for:
- **IT Auditors** who want automated, repeatable evidence instead of manual screenshots
- **Cloud GRC Teams** who need continuous control monitoring across Azure subscriptions
- **Cloud Security Engineers** building automated compliance pipelines

---

## Controls Covered (v1.0)

| Control ID | Control Name | NIST CSF 2.0 Ref | What This Tool Checks |
|---|---|---|---|
| ITGC-01 | Baseline Security Configuration | PR.IP-1 | Microsoft Defender for Cloud plan status across subscription |
| ITGC-02 | Activity Log Retention | DE.CM-1 | Activity log alert rules configured for critical actions |
| ITGC-03 | Privileged Access Review | PR.AC-4 | Direct Owner/Contributor role assignments to individual users |
| ITGC-04 | Security Contact Configuration | PR.AC-7 | Security contact email configured in Defender for Cloud |

> **Why these four?** These represent the most common ITGC findings in Azure cloud audits: missing security baseline, absent logging, over-privileged access, and missing incident notification. Together they map to the NIST CSF "Protect" and "Detect" functions — the same framework referenced in SOC 2 Type II and ISO 27001 assessments.

---

## Example Output

```
================================================================
  AZURE ITGC COMPLIANCE CHECKER  |  v1.0
  Subscription : Azure for Students
  Sub ID       : 4a9147de...
  Run Date     : 2026-05-09
================================================================

  ITGC-01    Defender for Cloud (Baseline Security) [ PASS ]
             PR.IP-1  Defender Standard tier enabled for: Discovery, FoundationalCspm

  ITGC-02    Activity Log Retention                 [ PASS ]
             DE.CM-1  2 activity log alert(s) configured. Critical actions are being monitored.

  ITGC-03    Privileged Access Review               [ WARN ]
             PR.AC-4  2 direct high-privilege assignment(s) to individual users.
             Risk: Standing privileged access increases risk of unauthorized changes.

  ITGC-04    Security Contact Configuration         [ PASS ]
             PR.AC-7  Security contact configured: admin@example.com

----------------------------------------------------------------
  Results: 3 PASS  |  0 FAIL  |  1 WARN
  Overall Risk Rating: LOW
----------------------------------------------------------------

  Full report saved to: itgc_report_20260509_143022.json
```

---

## Project Structure

```
azure-itgc-compliance-checker/
├── src/
│   ├── main.py           # CLI entry point — orchestrates all checks
│   ├── azure_client.py   # Azure authentication + SDK client factory
│   ├── checks.py         # Individual ITGC control check functions
│   └── report.py         # Console output formatting + JSON export
├── config.example.json   # Template — copy to config.json and fill in Sub ID
├── requirements.txt      # Python dependencies
├── CHANGELOG.md          # Version history
├── CONTRIBUTING.md       # How to add new controls
├── .gitignore            # config.json and reports excluded
└── README.md
```

---

## Prerequisites

- Python 3.9+
- An Azure subscription (free tier works: [portal.azure.com](https://portal.azure.com))
- Azure CLI installed and authenticated

---

## Setup

**1. Clone the repo**
```bash
git clone https://github.com/andres-banuelos/azure-itgc-compliance-checker.git
cd azure-itgc-compliance-checker
```

**2. Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure your subscription**
```bash
cp config.example.json config.json
# Open config.json and paste your Azure Subscription ID
```

**5. Authenticate with Azure CLI**
```bash
az login
```

**6. Run the checker**
```bash
python src/main.py --config config.json
```

**Optional — skip saving the JSON report:**
```bash
python src/main.py --config config.json --no-save
```

---

## Output Files

Each run saves a timestamped JSON report to the project root:
```
itgc_report_20260509_143022.json
```

The JSON report contains the full structured finding for each control — suitable for import into a GRC platform, ticket system, or audit workpaper.

> **Note:** Report files are excluded from version control via `.gitignore`. Do not commit them — they may contain subscription metadata.

---

## Audit Context

Each control maps to a real audit procedure tested in SOX ITGC walkthroughs:

- **ITGC-01 (Defender for Cloud)** — Tests the "security configuration management" ITGC category. Free-tier-only subscriptions lack threat detection and vulnerability assessment, which is a common finding in cloud ITGC assessments.
- **ITGC-02 (Activity Logs)** — Supports the "monitoring and logging" ITGC. Absence of log export or alert rules is a control gap that can result in qualified opinions during SOC 2 audits.
- **ITGC-03 (Privileged Access)** — Maps to "logical access" ITGCs. Direct Owner/Contributor assignments to individual user accounts (instead of PIM or group-based RBAC) represent a segregation of duties risk.
- **ITGC-04 (Security Contact)** — Supports "access authentication" and "incident response" ITGCs. Missing security contact configuration means critical alerts from Defender for Cloud have no notification path.

---

## Engineering Notes

This tool was built against `azure-mgmt-security` v7, which introduced breaking changes:

- **`pricings.list()`** now returns a `PricingList` object (not iterable directly) — handled via `.value` attribute check.
- **`securityContacts` API** has a deserialization bug in the SDK for certain tenant types — bypassed using a direct REST call via `requests`.
- **Azure for Students** subscriptions return the security contacts response as a raw JSON array rather than the standard ARM `{"value": [...]}` envelope — handled with an `isinstance` check.

These are real production-grade debugging patterns, not tutorial-level code.

---

## Roadmap

- [ ] v1.1 — Expand to 10 controls (NSG rules, storage encryption, Key Vault access policies)
- [ ] v1.2 — Add ISO 27001 Annex A control mapping alongside NIST CSF
- [ ] v1.3 — PDF report export for audit workpaper attachment
- [ ] v2.0 — GitHub Actions workflow for continuous compliance monitoring on a schedule

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## Contributing

Want to add a new control check? See [CONTRIBUTING.md](CONTRIBUTING.md) for the pattern and conventions used across all checks.

---

## Author

**Andres Banuelos** | IT Audit Analyst @ Deloitte | Cloud Security & GRC

Built from hands-on SOX ITGC audit experience with Fortune 50 clients. Designed to bridge the gap between manual audit evidence collection and cloud security automation.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/andres-banuelos)
