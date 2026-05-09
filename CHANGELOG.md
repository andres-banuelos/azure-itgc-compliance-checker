# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-05-09

### Added
- ITGC-01: Defender for Cloud plan status check (PR.IP-1)
- ITGC-02: Activity log alert rules check (DE.CM-1)
- ITGC-03: Privileged access review — direct Owner/Contributor assignments (PR.AC-4)
- ITGC-04: Security contact email configuration check (PR.AC-7)
- CLI entry point with `--config` and `--no-save` flags
- Timestamped JSON report output
- NIST CSF 2.0 control mapping on all findings
- Risk statements on WARN and FAIL findings

### Fixed
- `pricings.list()` returns non-iterable `PricingList` in azure-mgmt-security v7 — resolved via `.value` attribute
- `securityContacts` SDK deserialization error on Python 3.12 — bypassed with direct REST call
- Azure for Students tenants return security contacts as raw JSON array instead of ARM envelope — handled with `isinstance` check

---

## [Unreleased]

### Planned
- NSG inbound rule review (ITGC-05)
- Storage account public access check (ITGC-06)
- Key Vault access policy review (ITGC-07)
- ISO 27001 Annex A control mapping
- PDF report export
- GitHub Actions continuous monitoring workflow
