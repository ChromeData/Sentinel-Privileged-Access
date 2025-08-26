"""Execute each detection against a real Kusto engine, with decoys.

Every test here plants one true positive and at least one near-miss that must
NOT fire. The near-misses are the point. A rule that returns the attack row is
easy; a rule that returns the attack row and nothing else is a detection.

See kusto_harness.py for what this does and does not prove.
"""

import pytest

from kusto_harness import ensure_schema, ingest, kusto_available, reset, run  # noqa: F401

# The skip has to live HERE, in the test module.
#
# It was originally declared as pytestmark inside kusto_harness.py, which does
# nothing: pytest only collects pytestmark from modules it collects as tests.
# The skip silently never applied, and the first CI run errored 11 times with
# connection refused instead of skipping cleanly.
#
# Same family as everything else in these labs, inverted: not a green result
# that checked nothing, but a guard that looked present and was not wired up.
pytestmark = pytest.mark.skipif(
    not kusto_available(),
    reason="Kusto emulator not running; see kusto_harness.py for the docker command",
)


@pytest.fixture(scope="module", autouse=True)
def schema():
    ensure_schema()


# --- self-service privileged role assignment --------------------------------


def test_self_service_role_assignment():
    reset("AuditLogs")
    ingest("AuditLogs", """
    datatable(TimeGenerated:datetime, OperationName:string, Result:string,
              InitiatedBy:dynamic, TargetResources:dynamic, CorrelationId:string)
    [
      // TRUE POSITIVE: mallory grants herself Global Administrator.
      datetime(2026-08-12T10:00:00Z), "Add member to role", "success",
        dynamic({"user":{"userPrincipalName":"mallory@corp.com"}}),
        dynamic([{"userPrincipalName":"mallory@corp.com",
                  "modifiedProperties":[{"newValue":"x"},{"newValue":"Global Administrator"}]}]),
        "hit",

      // DECOY: an admin grants GA to someone else. Legitimate administration.
      datetime(2026-08-12T10:05:00Z), "Add member to role", "success",
        dynamic({"user":{"userPrincipalName":"admin@corp.com"}}),
        dynamic([{"userPrincipalName":"bob@corp.com",
                  "modifiedProperties":[{"newValue":"x"},{"newValue":"Global Administrator"}]}]),
        "other-target",

      // DECOY: self-assignment, but of a role nobody cares about.
      datetime(2026-08-12T10:09:00Z), "Add member to role", "success",
        dynamic({"user":{"userPrincipalName":"carol@corp.com"}}),
        dynamic([{"userPrincipalName":"carol@corp.com",
                  "modifiedProperties":[{"newValue":"x"},{"newValue":"Reports Reader"}]}]),
        "unprivileged-role",

      // DECOY: self-assignment of GA that FAILED. No escalation occurred.
      datetime(2026-08-12T10:11:00Z), "Add member to role", "failure",
        dynamic({"user":{"userPrincipalName":"dave@corp.com"}}),
        dynamic([{"userPrincipalName":"dave@corp.com",
                  "modifiedProperties":[{"newValue":"x"},{"newValue":"Global Administrator"}]}]),
        "failed-attempt"
    ]""")

    hits = run("detections/self-service-role-assignment.yaml")
    assert [h["CorrelationId"] for h in hits] == ["hit"]
    assert hits[0]["roleName"] == "Global Administrator"
    assert hits[0]["actor"] == hits[0]["target"]


def test_self_service_matches_eligible_assignments_too():
    """PIM 'Add eligible member to role' is in scope, and should be.

    Eligible assignment is still self-granted privilege; it just needs an
    activation step. A rule that only watched active assignment would miss the
    PIM path entirely.
    """
    reset("AuditLogs")
    ingest("AuditLogs", """
    datatable(TimeGenerated:datetime, OperationName:string, Result:string,
              InitiatedBy:dynamic, TargetResources:dynamic, CorrelationId:string)
    [
      datetime(2026-08-12T11:00:00Z), "Add eligible member to role", "success",
        dynamic({"user":{"userPrincipalName":"eve@corp.com"}}),
        dynamic([{"userPrincipalName":"eve@corp.com",
                  "modifiedProperties":[{"newValue":"x"},{"newValue":"Privileged Role Administrator"}]}]),
        "pim"
    ]""")

    hits = run("detections/self-service-role-assignment.yaml")
    assert [h["CorrelationId"] for h in hits] == ["pim"]


def test_self_service_case_insensitive_upn_match():
    """actor =~ target is a case-insensitive compare, and must stay that way.

    Entra is inconsistent about UPN casing between InitiatedBy and
    TargetResources. Switching =~ to == would silently stop detecting.
    """
    reset("AuditLogs")
    ingest("AuditLogs", """
    datatable(TimeGenerated:datetime, OperationName:string, Result:string,
              InitiatedBy:dynamic, TargetResources:dynamic, CorrelationId:string)
    [
      datetime(2026-08-12T12:00:00Z), "Add member to role", "success",
        dynamic({"user":{"userPrincipalName":"Mallory@Corp.com"}}),
        dynamic([{"userPrincipalName":"mallory@corp.com",
                  "modifiedProperties":[{"newValue":"x"},{"newValue":"User Administrator"}]}]),
        "case"
    ]""")

    hits = run("detections/self-service-role-assignment.yaml")
    assert [h["CorrelationId"] for h in hits] == ["case"], \
        "UPN casing differs between Entra fields; the compare must be case-insensitive"


# --- Key Vault bulk secret read ---------------------------------------------


def test_keyvault_bulk_read_fires_on_burst():
    """A quiet identity suddenly pulling 50 secrets in an hour."""
    reset("AzureDiagnostics")
    ingest("AzureDiagnostics", """
    range i from 1 to 50 step 1
    | project TimeGenerated = ago(10m),
              ResourceType = "VAULTS",
              OperationName = "SecretGet",
              Resource = strcat("vault", i % 3),
              identity_claim_upn_s = "burst@corp.com"
    """)

    hits = run("detections/keyvault-bulk-secret-read.yaml")
    upns = [h["identity_claim_upn_s"] for h in hits]
    assert "burst@corp.com" in upns
    hit = next(h for h in hits if h["identity_claim_upn_s"] == "burst@corp.com")
    assert hit["reads"] == 50
    assert hit["vaults"] == 3


def test_keyvault_bulk_read_ignores_low_volume():
    """Under the floor of 20, nothing fires regardless of baseline.

    Without the min-20 floor, an identity whose historical mean is near zero
    would alert on its third read of the day. That floor is why this stays
    quiet.
    """
    reset("AzureDiagnostics")
    ingest("AzureDiagnostics", """
    range i from 1 to 5 step 1
    | project TimeGenerated = ago(10m),
              ResourceType = "VAULTS",
              OperationName = "SecretGet",
              Resource = "vault0",
              identity_claim_upn_s = "quiet@corp.com"
    """)

    hits = run("detections/keyvault-bulk-secret-read.yaml")
    assert not any(h["identity_claim_upn_s"] == "quiet@corp.com" for h in hits)


def test_keyvault_bulk_read_ignores_other_operations():
    """SecretList and vault reads that are not SecretGet must not count.

    Enumerating secret NAMES is not reading their values, and conflating the
    two produces alerts on every backup job that lists a vault.
    """
    reset("AzureDiagnostics")
    ingest("AzureDiagnostics", """
    range i from 1 to 80 step 1
    | project TimeGenerated = ago(10m),
              ResourceType = "VAULTS",
              OperationName = "SecretList",
              Resource = "vault0",
              identity_claim_upn_s = "lister@corp.com"
    """)

    hits = run("detections/keyvault-bulk-secret-read.yaml")
    assert not any(h["identity_claim_upn_s"] == "lister@corp.com" for h in hits)


# --- break-glass off-hours (hunting) ----------------------------------------


def test_break_glass_off_hours():
    reset("SigninLogs")
    reset("Watchlist")
    ingest("Watchlist", """
    datatable(WatchlistAlias:string, UserPrincipalName:string)
    ["BreakGlassAccounts", "breakglass@corp.com"]
    """)
    ingest("SigninLogs", """
    datatable(TimeGenerated:datetime, UserPrincipalName:string, ResultType:int,
              IPAddress:string, AppDisplayName:string)
    [
      // TRUE POSITIVE: 03:00, well outside the window.
      datetime(2026-08-12T03:00:00Z), "breakglass@corp.com", 0, "1.2.3.4", "Portal",
      // DECOY: same account, 14:00, inside business hours.
      datetime(2026-08-12T14:00:00Z), "breakglass@corp.com", 0, "1.2.3.4", "Portal",
      // DECOY: 03:00 but an ordinary account, not on the watchlist.
      datetime(2026-08-12T03:30:00Z), "normal@corp.com", 0, "1.2.3.4", "Portal"
    ]""")

    hits = run("hunting/break-glass-off-hours.yaml")
    assert len(hits) == 1, f"expected only the off-hours break-glass sign-in, got {hits}"
    assert hits[0]["UserPrincipalName"] == "breakglass@corp.com"
    assert hits[0]["localHour"] == 3


def test_break_glass_boundary_is_inclusive_at_start_exclusive_at_end():
    """08:00 is business hours, 18:00 is not.

    The query uses `< businessStart or >= businessEnd`. Off-by-one here either
    floods the hunt with 8am logins or hides a 6pm one.
    """
    reset("SigninLogs")
    reset("Watchlist")
    ingest("Watchlist", """
    datatable(WatchlistAlias:string, UserPrincipalName:string)
    ["BreakGlassAccounts", "breakglass@corp.com"]
    """)
    ingest("SigninLogs", """
    datatable(TimeGenerated:datetime, UserPrincipalName:string, ResultType:int,
              IPAddress:string, AppDisplayName:string)
    [
      datetime(2026-08-12T08:00:00Z), "breakglass@corp.com", 0, "1.2.3.4", "in-window",
      datetime(2026-08-12T18:00:00Z), "breakglass@corp.com", 0, "1.2.3.4", "out-window"
    ]""")

    hits = run("hunting/break-glass-off-hours.yaml")
    assert [h["AppDisplayName"] for h in hits] == ["out-window"]


# --- dormant privileged account reactivation --------------------------------
#
# The rule is ago()-relative, so the fixtures must be too. datatable() only
# accepts compile-time constants and ago() is not one, so the offset goes in the
# literal as a number and becomes a timestamp in the following extend.


SIGNIN_COLS = """datatable(offsetDays:real, UserPrincipalName:string, ResultType:int,
                           IPAddress:string, AppDisplayName:string)"""


def signins(rows):
    """Build SigninLogs rows positioned relative to now."""
    return f"""{SIGNIN_COLS}
    [{rows}]
    | extend TimeGenerated = ago(offsetDays * 1d)
    | project TimeGenerated, UserPrincipalName, ResultType, IPAddress, AppDisplayName"""


def test_dormant_account_reactivation_fires():
    reset("SigninLogs")
    reset("Watchlist")
    ingest("Watchlist", """
    datatable(WatchlistAlias:string, UserPrincipalName:string)
    [
      "PrivilegedAccounts", "dormant@corp.com",
      "PrivilegedAccounts", "active@corp.com"
    ]""")
    ingest("SigninLogs", signins("""
      // TRUE POSITIVE: silent for 60 days, then signs in now.
      60.0, "dormant@corp.com", 0, "1.2.3.4", "Portal",
      0.0,  "dormant@corp.com", 0, "9.9.9.9", "Portal",

      // DECOY: privileged but regular; a 10-day gap is under the threshold.
      10.0, "active@corp.com", 0, "1.2.3.4", "Portal",
      0.0,  "active@corp.com", 0, "1.2.3.4", "Portal"
    """))

    hits = run("detections/dormant-privileged-account-reactivation.yaml")
    upns = [h["UserPrincipalName"] for h in hits]
    assert "dormant@corp.com" in upns, "a 60-day gap must exceed the 30-day threshold"
    assert "active@corp.com" not in upns, "a 10-day gap is normal and must not fire"
    hit = next(h for h in hits if h["UserPrincipalName"] == "dormant@corp.com")
    assert 55 <= hit["idleDays"] <= 65, f"idleDays should be ~60, got {hit['idleDays']}"


def test_dormant_ignores_unprivileged_accounts():
    """Not on the watchlist, not in scope, however long the gap."""
    reset("SigninLogs")
    reset("Watchlist")
    ingest("Watchlist", """
    datatable(WatchlistAlias:string, UserPrincipalName:string)
    ["PrivilegedAccounts", "someone-else@corp.com"]
    """)
    ingest("SigninLogs", signins("""
      80.0, "nobody@corp.com", 0, "1.2.3.4", "Portal",
      0.0,  "nobody@corp.com", 0, "1.2.3.4", "Portal"
    """))

    hits = run("detections/dormant-privileged-account-reactivation.yaml")
    assert not any(h["UserPrincipalName"] == "nobody@corp.com" for h in hits)


def test_dormant_ignores_failed_signins():
    """ResultType != 0 is a failed sign-in, not a reactivation.

    Counting failures would turn every password-spray against a dormant admin
    into a "the account is back" alert, which inverts what the rule means.
    """
    reset("SigninLogs")
    reset("Watchlist")
    ingest("Watchlist", """
    datatable(WatchlistAlias:string, UserPrincipalName:string)
    ["PrivilegedAccounts", "sprayed@corp.com"]
    """)
    ingest("SigninLogs", signins("""
      60.0, "sprayed@corp.com", 0,     "1.2.3.4", "Portal",
      0.0,  "sprayed@corp.com", 50126, "6.6.6.6", "Portal"
    """))

    hits = run("detections/dormant-privileged-account-reactivation.yaml")
    assert not any(h["UserPrincipalName"] == "sprayed@corp.com" for h in hits),         "a failed sign-in is not a reactivation"
