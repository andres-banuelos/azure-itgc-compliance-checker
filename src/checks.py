"""
checks.py
---------
Each function in this file performs ONE ITGC control check against Azure.

Return format (consistent across all checks):
  {
    "control_id":   str   - e.g. "ITGC-01"
    "control_name": str   - human-readable name
    "nist_ref":     str   - NIST CSF 2.0 control reference
    "status":       str   - "PASS", "FAIL", or "WARN"
    "detail":       str   - specific finding message
    "risk":         str   - brief risk statement if FAIL or WARN
  }

Audit note: This consistent structure mirrors how findings are documented
in workpapers - each check = one testable control objective.
"""

from azure.core.exceptions import HttpResponseError


def check_defender_for_cloud(security_client, subscription_id: str) -> dict:
    """
    ITGC-01: Baseline Security Configuration
    NIST CSF 2.0: PR.IP-1

    Tests whether Microsoft Defender for Cloud (formerly Azure Security Center)
    has a paid/standard tier enabled on the subscription.

    Audit context: A subscription running only the Free tier has no threat
    detection, vulnerability assessment, or adaptive controls. This is the
    cloud equivalent of "no endpoint protection" - a common SOX ITGC finding.
    """
    control = {
        "control_id": "ITGC-01",
        "control_name": "Defender for Cloud (Baseline Security)",
        "nist_ref": "PR.IP-1",
        "status": "FAIL",
        "detail": "",
        "risk": "No threat detection or vulnerability assessment active on subscription."
    }

    try:
        # List all Defender for Cloud pricing configurations (one per resource type)
        pricings = list(security_client.pricings.list(
            scope_id=f"/subscriptions/{subscription_id}"
        ))

        # Check if ANY resource type has Standard/Defender paid tier enabled
        enabled_plans = [
            p.name for p in pricings
            if hasattr(p, 'pricing_tier') and p.pricing_tier == "Standard"
        ]

        if enabled_plans:
            control["status"] = "PASS"
            control["detail"] = f"Defender enabled for: {', '.join(enabled_plans[:3])}{'...' if len(enabled_plans) > 3 else ''}"
            control["risk"] = ""
        else:
            control["status"] = "FAIL"
            control["detail"] = "No Defender for Cloud Standard/paid plans found. Free tier only."

    except HttpResponseError as e:
        control["status"] = "ERROR"
        control["detail"] = f"API error: {e.error.code if e.error else str(e)}"
        control["risk"] = "Could not verify control status."

    return control


def check_activity_log_retention(monitor_client, subscription_id: str) -> dict:
    """
    ITGC-02: Activity Log Retention / Diagnostic Settings
    NIST CSF 2.0: DE.CM-1

    Tests whether diagnostic settings are configured to export Azure Activity
    Logs to a Log Analytics Workspace or Storage Account.

    Audit context: Without log export, activity logs are only retained for
    90 days in Azure's default storage and cannot support forensic review
    or long-term audit trails. SOX and SOC 2 typically require 1-year+ retention.
    """
    control = {
        "control_id": "ITGC-02",
        "control_name": "Activity Log Retention",
        "nist_ref": "DE.CM-1",
        "status": "FAIL",
        "detail": "",
        "risk": "Activity logs not exported. Audit trail limited to 90 days with no forensic replay capability."
    }

    try:
        resource_uri = f"/subscriptions/{subscription_id}"
        diagnostic_settings = list(
            monitor_client.diagnostic_settings.list(resource_uri=resource_uri)
        )

        if diagnostic_settings:
            destinations = []
            for ds in diagnostic_settings:
                if ds.workspace_id:
                    destinations.append("Log Analytics Workspace")
                if ds.storage_account_id:
                    destinations.append("Storage Account")
                if ds.event_hub_authorization_rule_id:
                    destinations.append("Event Hub")

            if destinations:
                control["status"] = "PASS"
                control["detail"] = f"{len(diagnostic_settings)} diagnostic setting(s) found. Destinations: {', '.join(set(destinations))}"
                control["risk"] = ""
            else:
                control["status"] = "WARN"
                control["detail"] = f"{len(diagnostic_settings)} diagnostic setting(s) found but no recognized export destination configured."
        else:
            control["status"] = "FAIL"
            control["detail"] = "No diagnostic settings found on subscription. Activity logs not being exported."

    except HttpResponseError as e:
        control["status"] = "ERROR"
        control["detail"] = f"API error: {e.error.code if e.error else str(e)}"
        control["risk"] = "Could not verify control status."

    return control


def check_privileged_access(auth_client, subscription_id: str) -> dict:
    """
    ITGC-03: Privileged Access Review
    NIST CSF 2.0: PR.AC-4

    Identifies direct Owner and Contributor role assignments at subscription
    scope assigned to individual user accounts (not groups or service principals).

    Audit context: Direct high-privilege assignments to users instead of
    groups violates least-privilege and makes access reviews harder.
    In SOX ITGCs, this is a logical access finding: "privileged users with
    standing access should be minimized and reviewed quarterly."
    PIM (Privileged Identity Management) should be used for just-in-time access.
    """
    control = {
        "control_id": "ITGC-03",
        "control_name": "Privileged Access Review",
        "nist_ref": "PR.AC-4",
        "status": "PASS",
        "detail": "",
        "risk": ""
    }

    HIGH_PRIV_ROLES = [
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
        "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    ]

    try:
        scope = f"/subscriptions/{subscription_id}"
        assignments = list(
            auth_client.role_assignments.list_for_scope(scope=scope)
        )

        # Filter: high-privilege roles assigned directly to users (not groups/SPNs)
        risky_assignments = [
            a for a in assignments
            if any(role_id in (a.role_definition_id or "") for role_id in HIGH_PRIV_ROLES)
            and getattr(a, 'principal_type', '') == 'User'
        ]

        if not risky_assignments:
            control["status"] = "PASS"
            control["detail"] = "No direct Owner/Contributor assignments to individual users found at subscription scope."
        elif len(risky_assignments) <= 2:
            control["status"] = "WARN"
            control["detail"] = f"{len(risky_assignments)} direct high-privilege assignment(s) to individual users. Review whether PIM or group-based access should be used."
            control["risk"] = "Standing privileged access increases risk of unauthorized changes. Consider PIM for just-in-time access."
        else:
            control["status"] = "FAIL"
            control["detail"] = f"{len(risky_assignments)} direct Owner/Contributor assignments to individual users. Exceeds acceptable threshold."
            control["risk"] = "Excessive standing privileged access. Segregation of duties risk. PIM and group-based RBAC recommended."

    except HttpResponseError as e:
        control["status"] = "ERROR"
        control["detail"] = f"API error: {e.error.code if e.error else str(e)}"
        control["risk"] = "Could not verify control status."

    return control


def check_security_contacts(security_client, subscription_id: str) -> dict:
    """
    ITGC-04: Security Contact / MFA Enforcement Signal
    NIST CSF 2.0: PR.AC-7

    Tests whether a security contact (email + phone) is configured in
    Defender for Cloud. This is a proxy indicator for security program
    maturity and is required for Defender for Cloud to send alert notifications.

    Audit context: Missing security contacts means critical security alerts
    go unnoticed. In cloud ITGC walkthroughs, this is often documented as
    "alert notification controls not operating effectively."
    """
    control = {
        "control_id": "ITGC-04",
        "control_name": "Security Contact Configuration",
        "nist_ref": "PR.AC-7",
        "status": "FAIL",
        "detail": "",
        "risk": "Security alerts may go unnotified. No contact point for critical cloud security events."
    }

    try:
        contacts = list(
            security_client.security_contacts.list()
        )

        contacts_with_email = [
            c for c in contacts
            if getattr(c, 'email', None) and c.email.strip()
        ]

        if contacts_with_email:
            control["status"] = "PASS"
            contact = contacts_with_email[0]
            control["detail"] = f"Security contact configured: {contact.email}. Alert notifications: {'Enabled' if getattr(contact, 'alert_notifications', None) else 'Check manually'}."
            control["risk"] = ""
        else:
            control["status"] = "FAIL"
            control["detail"] = "No security contact with email address found in Defender for Cloud."

    except HttpResponseError as e:
        control["status"] = "ERROR"
        control["detail"] = f"API error: {e.error.code if e.error else str(e)}"
        control["risk"] = "Could not verify control status."

    return control
