import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "purge-operator-evidence.py"

spec = importlib.util.spec_from_file_location("purge_operator_evidence", SCRIPT)
purge_operator_evidence = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(purge_operator_evidence)


class PurgeOperatorEvidenceTests(unittest.TestCase):
    def make_fixture(self, root: Path):
        log_dir = root / "var/log/cowrie"
        tty_dir = root / "var/lib/cowrie/tty"
        download_dir = root / "var/lib/cowrie/downloads"
        log_dir.mkdir(parents=True)
        tty_dir.mkdir(parents=True)
        download_dir.mkdir(parents=True)
        operator_tty = tty_dir / "operator-session.tty"
        attacker_tty = tty_dir / "attacker-session.tty"
        operator_download = download_dir / "operator.bin"
        operator_tty.write_text("operator evidence", encoding="utf-8")
        attacker_tty.write_text("attacker evidence", encoding="utf-8")
        operator_download.write_text("not executable", encoding="utf-8")
        events = [
            {"eventid": "cowrie.session.connect", "src_ip": "203.0.113.10", "session": "operator-session"},
            {"eventid": "cowrie.log.open", "session": "operator-session", "ttylog": str(operator_tty)},
            {"eventid": "cowrie.session.file_download", "session": "operator-session", "outfile": str(operator_download)},
            {"eventid": "cowrie.session.connect", "src_ip": "8.8.8.8", "session": "attacker-session"},
        ]
        current = log_dir / "cowrie.json"
        current.write_text("".join(json.dumps(event) + "\n" for event in events[:3]), encoding="utf-8")
        rotated = log_dir / "cowrie.json.1.gz"
        with gzip.open(rotated, "wt", encoding="utf-8") as handle:
            handle.write(json.dumps(events[3]) + "\n")
        (log_dir / "cowrie.log").write_text(
            "operator-session 203.0.113.10 controlled test\nattacker-session 8.8.8.8 retained\n",
            encoding="utf-8",
        )
        return operator_tty, attacker_tty, operator_download

    def test_dry_run_does_not_modify_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operator_tty, attacker_tty, operator_download = self.make_fixture(root)
            before = (root / "var/log/cowrie/cowrie.json").read_bytes()
            report = purge_operator_evidence.purge(root, {"203.0.113.10"})
            self.assertEqual(report["operator_sessions"], 1)
            self.assertEqual(report["json_lines_removed"], 3)
            self.assertEqual(report["text_lines_removed"], 1)
            self.assertEqual(report["evidence_files_removed"], 2)
            self.assertEqual((root / "var/log/cowrie/cowrie.json").read_bytes(), before)
            self.assertTrue(operator_tty.exists())
            self.assertTrue(operator_download.exists())
            self.assertTrue(attacker_tty.exists())

    def test_apply_removes_only_operator_session(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            operator_tty, attacker_tty, operator_download = self.make_fixture(root)
            report = purge_operator_evidence.purge(root, {"203.0.113.10"}, apply=True)
            self.assertEqual(report["mode"], "apply")
            rendered = "".join(
                path.read_text(encoding="utf-8", errors="replace")
                for path in (root / "var/log/cowrie").glob("*.log")
            )
            self.assertNotIn("203.0.113.10", rendered)
            self.assertNotIn("operator-session", rendered)
            self.assertIn("attacker-session", rendered)
            self.assertFalse(operator_tty.exists())
            self.assertFalse(operator_download.exists())
            self.assertTrue(attacker_tty.exists())
            with gzip.open(root / "var/log/cowrie/cowrie.json.1.gz", "rt", encoding="utf-8") as handle:
                self.assertIn("attacker-session", handle.read())


if __name__ == "__main__":
    unittest.main()
