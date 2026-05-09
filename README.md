# Azure ITGC Compliance Checker

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

| Control ID | Control Name | NIST CSF 2.0 Reference | What This Tool Checks |
|---|---|---|---|
| ITGC-01 | Baseline Security Configuration | PR.IP-1 | Microsoft Defender for Cloud enabled on subscription |
| ITGC-02 | Activity Log Retention | DE.CM-1 | Diagnostic settings configured to export Activity Logs |
| ITGC-03 | Privileged Access Review | PR.AC-4 | Owner/Contributor role assignments at subscription scope |
| ITGC-04 | MFA Enforcement | PR.AC-7 | Security contacts and MFA-related policy presence |

> **Why these controls?** These four represent the most common ITGC findings in Azure cloud audits: missing security baseline, absent logging, over-privileged access, and weak authentication controls. Together they map to the NIST CSF "Protect" and "Detect" functions — the same framework referenced in SOC 2 Type II and ISO 27001 assessments.

---

## Project Structure

```
azure-itgc-compliance-checker/
├── src/
│   ├── main.py              # CLI entry point
│   ├── azure_client.py     # Azure authentication wrapper
│   ├── checks.py           # Individual ITGC control checks
│   └── report.py           # Output formatting
├── config.example.json     # Template for subscription config
├── requirements.txt        # Python dependencies
├── .gitignore
└── README.md
```

---

## Prerequisites

- Python 3.9+
- An Azure subscription (free tier works: [portal.azure.com](https://portal.azure.com))
- Azure CLI installed and authenticated (`az login`)

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
source venv/bin/activate  # Windows: venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Configure your subscription**
```bash
cp config.example.json config.json
# Edit config.json with your Azure Subscription ID
```

**5. Authenticate with Azure**
```bash
az login
```

**6. Run the checker**
```bash
python src/main.py --config config.json
```

---

## Example Output

```
================================================
  AZURE ITGC COMPLIANCE CHECKER  |  v1.0
  Subscription: My Azure Subscription
  Run Date: 2026-05-09
================================================

  ITGC-01  Defender for Cloud        [ PASS ]  Standard tier enabled
  ITGC-02  Activity Log Retention    [ FAIL ]  No diagnostic settings found
  ITGC-03  Privileged Access Review  [ WARN ]  3 direct Owner assignments found
  ITGC-04  MFA Enforcement           [ WARN ]  No security contact configured

------------------------------------------------
  Results: 1 PASS  |  1 FAIL  |  2 WARN
  Risk Rating: MEDIUM
------------------------------------------------

Full report saved to: itgc_report_20260509.json
```

---

## Audit Context

Each finding in this tool maps to a real audit procedure:

- **ITGC-01 (Defender for Cloud)**: Equivalent to testing that a security baseline / endpoint protection control is in place. In SOX audits, this supports the "security configuration management" ITGC category.
- **ITGC-02 (Activity Logs)**: Supports the "monitoring and logging" ITGC. Absence of log export is a common control gap that leads to qualified opinions.
- **ITGC-03 (Privileged Access)**: Maps directly to "logical access" ITGCs. Direct Owner assignments to individual users (instead of groups/PIM) represent segregation of duties risk.
- **ITGC-04 (MFA)**: Supports "access authentication" ITGCs. Missing security contacts and MFA gaps are frequent findings in cloud ITGC walkthroughs.

---

## Roadmap

- [ ] v1.1 — Add JSON + PDF report export
- [ ] v1.2 — Expand to 10 controls (NSG rules, storage encryption, Key Vault access)
- [ ] v1.3 — Add ISO 27001 Annex A control mapping
- [ ] v2.0 — GitHub Actions workflow for continuous compliance monitoring

---

## Author

**Andres Banuelos** | IT Audit Analyst @ Deloitte | Cloud Security & GRC

Built from hands-on SOX ITGC audit experience with Fortune 50 clients. Designed to bridge the gap between audit evidence collection and cloud security automation.
