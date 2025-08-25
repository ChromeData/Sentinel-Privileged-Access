"""Offline tests for the detection validator, plus a real check that every
shipped detection passes.

The unit tests pin the rules. The `test_all_shipped_detections_valid` test is
the one that keeps CI honest: if a detection in this repo ever has a placeholder
GUID, a bad severity, or a misspelled tactic, CI goes red.

Run:  python -m pytest tests/ -v
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import importlib.util

spec = importlib.util.spec_from_file_location("validate", ROOT / "scripts" / "validate.py")
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


def good():
    return {
        "id": "690d1e33-607a-4adc-b22e-a8155ec52a4d",
        "name": "x",
        "description": "y",
        "severity": "High",
        "query": "SigninLogs | take 1",
        "tactics": ["InitialAccess"],
    }


class TestRules:
    def test_a_correct_detection_passes(self):
        assert validate.check_doc(good()) == []

    def test_missing_required_key_fails(self):
        d = good()
        del d["query"]
        assert any("missing keys" in e for e in validate.check_doc(d))

    def test_bad_severity_fails(self):
        d = good()
        d["severity"] = "Critical"  # not a Sentinel severity
        assert any("severity" in e for e in validate.check_doc(d))

    def test_misspelled_tactic_fails(self):
        d = good()
        d["tactics"] = ["PrivEsc"]  # real name is PrivilegeEscalation
        assert any("tactic" in e for e in validate.check_doc(d))

    def test_empty_query_fails(self):
        d = good()
        d["query"] = "   "
        assert any("empty query" in e for e in validate.check_doc(d))

    def test_placeholder_guid_fails(self):
        d = good()
        d["id"] = "6f1a2b3c-0000-4d00-8000-lab0000001"
        assert any("placeholder" in e for e in validate.check_doc(d))


class TestHuntingSchema:
    def test_hunting_query_without_severity_is_valid(self):
        # A hunting query is not an alert; requiring severity is a category error.
        d = {
            "id": "f5b3bfd3-a053-428c-bc4b-7bdb6c34bfd0",
            "name": "x",
            "description": "y",
            "query": "SigninLogs | take 1",
        }
        assert validate.check_doc(d, hunting=True) == []

    def test_same_doc_fails_as_a_detection(self):
        # The relaxation must be explicit - the default schema still wants severity.
        d = {
            "id": "f5b3bfd3-a053-428c-bc4b-7bdb6c34bfd0",
            "name": "x",
            "description": "y",
            "query": "SigninLogs | take 1",
        }
        assert any("severity" in e for e in validate.check_doc(d, hunting=False))


class TestShipped:
    """The detections actually in this repo must all validate."""

    files = sorted((ROOT / "detections").glob("*.yaml")) + \
        sorted((ROOT / "hunting").glob("*.yaml"))

    def test_there_are_detections(self):
        assert self.files, "no detection YAML found"

    @pytest.mark.parametrize("path", files, ids=[f.name for f in files])
    def test_all_shipped_detections_valid(self, path):
        errs = validate.check(path)
        assert errs == [], f"{path.name}: {errs}"
