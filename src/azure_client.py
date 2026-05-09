"""
azure_client.py
---------------
Handles Azure authentication and returns initialized SDK clients.

Why DefaultAzureCredential?
  It automatically tries multiple auth methods in order:
  1. Environment variables (CI/CD pipelines)
  2. Azure CLI login (your local `az login` session)  <-- what we use locally
  3. Managed Identity (when running on Azure VMs/Functions)

  This means the same code works locally AND in production without changes.
"""

from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import SubscriptionClient


def get_credential():
    """
    Returns a DefaultAzureCredential object.
    This will use your `az login` session when running locally.
    """
    return DefaultAzureCredential()


def get_security_client(credential, subscription_id: str) -> SecurityCenter:
    """
    Returns a SecurityCenter client for Defender for Cloud checks.
    Used for: ITGC-01 (Baseline Security Configuration)
    """
    return SecurityCenter(credential, subscription_id)


def get_monitor_client(credential, subscription_id: str) -> MonitorManagementClient:
    """
    Returns a MonitorManagementClient for Activity Log / Diagnostic Settings checks.
    Used for: ITGC-02 (Activity Log Retention)
    """
    return MonitorManagementClient(credential, subscription_id)


def get_authorization_client(credential, subscription_id: str) -> AuthorizationManagementClient:
    """
    Returns an AuthorizationManagementClient for RBAC / role assignment checks.
    Used for: ITGC-03 (Privileged Access Review)
    """
    return AuthorizationManagementClient(credential, subscription_id)


def get_subscription_client(credential) -> SubscriptionClient:
    """
    Returns a SubscriptionClient to look up subscription display name.
    Used for: report header / display name resolution.
    """
    return SubscriptionClient(credential)
