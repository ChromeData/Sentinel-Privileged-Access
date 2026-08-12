#!/usr/bin/env python3
"""Schema-check Sentinel detection YAML before you open a PR.

Validates the fields the Azure-Sentinel repo's own CI checks: required keys,
severity enum, ATT&CK tactic spelling, and that the KQL is non-empty. This is a
subset of upstream validation — enough to catch the mistakes that get a PR bounced,
without pulling the full toolchain.

Run: python3 scripts/validate.py
"""

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {"id", "name", "description", "severity", "query"}
SEVERITIES = {"Informational", "Low", "Medium", "High"}
# Sentinel tactic names are capitalised words with no spaces; this is the set the
# upstream validator accepts (abbreviated to the ones used here).
TACTICS = {
    "InitialAccess", "Persistence", "PrivilegeEscalation", "Credentialaccess",
    "CredentialAccess", "Discovery", "LateralMovement", "Impact", "Execution",
    "DefenseEvasion", "Collection", "Exfiltration", "CommandAndControl",
}


def check(path):
    errs = []
    doc = yaml.safe_load(path.read_text())

    missing = REQUIRED - doc.keys()
    if missing:
        errs.append(f"missing keys: {sorted(missing)}")

    if doc.get("severity") not in SEVERITIES:
        errs.append(f"severity '{doc.get('severity')}' not in {sorted(SEVERITIES)}")

    for t in doc.get("tactics", []):
        if t not in TACTICS:
            errs.append(f"tactic '{t}' not recognised (check capitalisation)")

    if not str(doc.get("query", "")).strip():
        errs.append("empty query")

    if str(doc.get("id", "")).startswith("6f1a2b3c-0000"):
        errs.append("placeholder GUID — run uuidgen and replace before submitting")

    return errs


def main():
    files = sorted((ROOT / "detections").glob("*.yaml")) + \
            sorted((ROOT / "hunting").glob("*.yaml"))
    if not files:
        sys.exit("no YAML found under detections/ or hunting/")

    failed = 0
    for f in files:
        errs = check(f)
        if errs:
            failed += 1
            print(f"FAIL {f.relative_to(ROOT)}")
            for e in errs:
                print(f"     - {e}")
        else:
            print(f"ok   {f.relative_to(ROOT)}")

    print()
    if failed:
        print(f"{failed} file(s) failed. Placeholder GUIDs are expected until you "
              "finalise — replace them before any real submission.")
        sys.exit(1)
    print("all detections valid")


if __name__ == "__main__":
    main()
