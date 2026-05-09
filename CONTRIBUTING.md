# Contributing — Adding a New Control Check

This project is structured so that each ITGC control is a single self-contained function in `src/checks.py`. Adding a new control takes about 30 minutes if you follow this pattern.

---

## Step 1 — Add the check function to `checks.py`

Every check function must:
- Accept the relevant Azure SDK client(s) and `subscription_id` as parameters
- Return a `dict` with exactly these keys:

```python
{
    "control_id":   str,   # e.g. "ITGC-05"
    "control_name": str,   # Human-readable name
    "nist_ref":     str,   # e.g. "PR.DS-1"
    "status":       str,   # "PASS", "FAIL", "WARN", or "ERROR"
    "detail":       str,   # Specific finding — what was found
    "risk":         str,   # Risk statement — empty string if PASS
}
```

Example skeleton:

```python
def check_storage_public_access(storage_client, subscription_id: str) -> dict:
    """
    ITGC-06: Storage Account Public Access
    NIST CSF 2.0: PR.DS-1

    Checks whether any storage accounts allow public blob access.
    """
    control = {
        "control_id": "ITGC-06",
        "control_name": "Storage Account Public Access",
        "nist_ref": "PR.DS-1",
        "status": "FAIL",
        "detail": "",
        "risk": "Public blob access exposes data to unauthenticated reads."
    }

    try:
        # ... your Azure SDK calls here ...
        pass

    except HttpResponseError as e:
        control["status"] = "ERROR"
        control["detail"] = f"API error: {e.error.code if e.error else str(e)}"
        control["risk"] = "Could not verify control status."

    return control
```

---

## Step 2 — Add the SDK client to `azure_client.py` (if needed)

If your check requires a new Azure SDK client, add a factory function:

```python
def get_storage_client(credential, subscription_id: str):
    from azure.mgmt.storage import StorageManagementClient
    return StorageManagementClient(credential, subscription_id)
```

---

## Step 3 — Wire it into `main.py`

1. Import the new function at the top of `main.py`
2. Instantiate the client in the client setup block
3. Add the function call to the `results = [...]` list

---

## Step 4 — Update the README controls table

Add a row to the Controls Covered table in `README.md`.

---

## Step 5 — Update CHANGELOG.md

Add an entry under `[Unreleased]` describing the new control.

---

## Conventions

- Status logic: PASS = control operating effectively, WARN = partial / needs review, FAIL = control not in place, ERROR = could not verify
- Always include a `risk` string for WARN and FAIL — empty string `""` for PASS
- Always wrap SDK calls in `except HttpResponseError` at minimum
- Prefer direct REST calls over SDK clients when the SDK has known deserialization issues (see ITGC-04 as a reference)
- Never hardcode subscription IDs, tenant IDs, or credentials in check functions
