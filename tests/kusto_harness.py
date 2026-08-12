"""Run the detection queries against a real Kusto engine.

Until this existed, nothing in this repo executed a single line of KQL. The
tests validated YAML structure: that a rule had a query field, sane frequency,
a MITRE technique. All useful, none of it evidence that the query runs, let
alone that it fires on an attack and stays quiet on normal activity.

Sentinel needs a Log Analytics workspace, which needs an Azure subscription.
But Microsoft ships the Kusto engine itself as a container,
mcr.microsoft.com/azuredataexplorer/kustainer-linux, free for dev and test.
Same query engine underneath Sentinel. So the queries can be executed for real,
against controlled data, with no subscription:

    docker run -d --name kustainer -e ACCEPT_EULA=Y -m 4G -p 8080:8080 \
      mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest

    python -m pytest tests/ -v

Skips cleanly when the container is not running, so CI stays green without it.

WHAT THIS PROVES
  The KQL parses, the column references resolve, the joins and dynamic-field
  extractions work, and each rule fires on the true positive while staying
  silent on the near-miss decoys. That last part is the whole point: a
  detection that fires on everything is as useless as one that fires on
  nothing, and structural validation cannot tell you which you have.

WHAT IT DOES NOT PROVE
  Sentinel-specific behaviour. Real table schemas carry columns these fixtures
  do not; ingestion lag, the incident pipeline and entity mapping are all
  Sentinel, not Kusto. _GetWatchlist is stubbed here (see below). Passing
  means the detection logic is sound, not that the rule is deployed and
  working in a tenant.
"""

import json
import os
import urllib.error
import urllib.request

import pytest
import yaml

from pathlib import Path

KUSTO = os.environ.get("KUSTO_URL", "http://localhost:8080")
ROOT = Path(__file__).resolve().parent.parent


def _post(endpoint, csl, database="NetDefaultDB"):
    body = json.dumps({"db": database, "csl": csl}).encode()
    req = urllib.request.Request(
        f"{KUSTO}/v1/rest/{endpoint}",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def kusto_available():
    try:
        _post("mgmt", ".show version")
        return True
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


pytestmark = pytest.mark.skipif(
    not kusto_available(),
    reason="Kusto emulator not running; see module docstring for the docker command",
)


def rows(result):
    """Extract the primary result table as a list of dicts."""
    table = next(t for t in result["Tables"] if t["TableName"] == "Table_0")
    cols = [c["ColumnName"] for c in table["Columns"]]
    return [dict(zip(cols, r)) for r in table["Rows"]]


# --- schema -----------------------------------------------------------------
#
# Only the columns the queries actually touch. Real Sentinel tables are far
# wider, and a query that works here can still fail there by referencing a
# column this schema omits. Narrow on purpose: a fixture that mirrors the full
# schema is a fixture nobody maintains.

SCHEMA = [
    """.create table AuditLogs (TimeGenerated: datetime, OperationName: string,
        Result: string, InitiatedBy: dynamic, TargetResources: dynamic,
        CorrelationId: string)""",
    """.create table SigninLogs (TimeGenerated: datetime, UserPrincipalName: string,
        ResultType: int, IPAddress: string, AppDisplayName: string)""",
    """.create table AzureDiagnostics (TimeGenerated: datetime, ResourceType: string,
        OperationName: string, Resource: string, identity_claim_upn_s: string)""",
    # Backing store for the _GetWatchlist stub below.
    """.create table Watchlist (WatchlistAlias: string, UserPrincipalName: string)""",
]

# _GetWatchlist is a Sentinel function, not a Kusto one. It does not exist in
# the engine, so any query using it fails to parse here.
#
# That is worth stating plainly rather than hiding: two of these four rules
# depend on a Sentinel-only construct, and this stub is the seam where local
# testing stops matching production. The stub returns the same shape (a table
# with UserPrincipalName), so the surrounding logic is genuinely exercised,
# but watchlist semantics in a real tenant, refresh timing, size limits, and
# the SearchKey column, are not.
WATCHLIST_STUB = """.create function with (docstring='Sentinel _GetWatchlist stub')
    _GetWatchlist(alias: string) {
        Watchlist | where WatchlistAlias == alias
    }"""


def ensure_schema():
    for stmt in SCHEMA:
        try:
            _post("mgmt", stmt)
        except urllib.error.HTTPError:
            pass  # already exists
    try:
        _post("mgmt", WATCHLIST_STUB)
    except urllib.error.HTTPError:
        pass


def reset(table):
    try:
        _post("mgmt", f".clear table {table} data")
    except urllib.error.HTTPError:
        pass


def ingest(table, datatable_literal):
    _post("mgmt", f".set-or-append {table} <| {datatable_literal}")


def query_of(rule_path):
    return yaml.safe_load((ROOT / rule_path).read_text(encoding="utf-8"))["query"]


def run(rule_path):
    return rows(_post("query", query_of(rule_path)))
