#!/usr/bin/env python3
"""Remove explicitly identified operator sessions from retained Cowrie evidence.

The default mode is read-only. Use --apply only while cowrie.service is stopped.
No backup containing the removed evidence is created.
"""

from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, TextIO


DEFAULT_HONEYPOT_ROOT = Path("/home/cowrie/honeypot")


def open_text(path: Path, mode: str) -> TextIO:
    if path.name.endswith(".gz"):
        return gzip.open(path, mode, encoding="utf-8", errors="replace")
    return path.open(mode, encoding="utf-8", errors="replace")


def read_lines(path: Path) -> list[str]:
    with open_text(path, "rt") as handle:
        return handle.readlines()


def event_session(event: dict[str, Any]) -> str | None:
    value = event.get("session")
    return value if isinstance(value, str) and value else None


def event_matches(event: dict[str, Any], operator_ips: set[str], sessions: set[str]) -> bool:
    source = str(event.get("src_ip") or "")
    session = event_session(event)
    return source in operator_ips or (session is not None and session in sessions)


def parse_json_line(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def resolve_evidence_path(value: Any, honeypot_root: Path, allowed_roots: Iterable[Path]) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else honeypot_root / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        return None
    for root in allowed_roots:
        try:
            resolved.relative_to(root.resolve(strict=False))
            return resolved
        except ValueError:
            continue
    return None


def atomic_rewrite(path: Path, lines: list[str]) -> None:
    original = path.stat()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        if path.name.endswith(".gz"):
            with gzip.open(temporary, "wt", encoding="utf-8", errors="replace") as handle:
                handle.writelines(lines)
        else:
            with temporary.open("wt", encoding="utf-8", errors="replace") as handle:
                handle.writelines(lines)
        os.chmod(temporary, original.st_mode)
        try:
            os.chown(temporary, original.st_uid, original.st_gid)
        except (AttributeError, PermissionError):
            pass
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def purge(
    honeypot_root: Path, operator_ips: set[str], apply: bool = False,
) -> dict[str, Any]:
    log_dir = honeypot_root / "var/log/cowrie"
    tty_root = (honeypot_root / "var/lib/cowrie/tty").resolve(strict=False)
    download_root = (honeypot_root / "var/lib/cowrie/downloads").resolve(strict=False)
    json_paths = sorted(path for path in log_dir.glob("cowrie.json*") if path.is_file())
    text_paths = sorted(path for path in log_dir.glob("cowrie.log*") if path.is_file())

    sessions: set[str] = set()
    for path in json_paths:
        for line in read_lines(path):
            event = parse_json_line(line)
            if event is not None and str(event.get("src_ip") or "") in operator_ips:
                session = event_session(event)
                if session:
                    sessions.add(session)

    json_removed = text_removed = 0
    event_types: Counter[str] = Counter()
    evidence_paths: set[Path] = set()
    rewrites: dict[Path, list[str]] = {}
    sensitive_values = operator_ips | sessions

    for path in json_paths:
        kept: list[str] = []
        for line in read_lines(path):
            event = parse_json_line(line)
            matched = event_matches(event, operator_ips, sessions) if event is not None else any(
                value and value in line for value in sensitive_values
            )
            if not matched:
                kept.append(line)
                continue
            json_removed += 1
            if event is not None:
                event_types[str(event.get("eventid") or "unknown")] += 1
                for key in ("ttylog", "outfile"):
                    evidence = resolve_evidence_path(event.get(key), honeypot_root, (tty_root, download_root))
                    if evidence is not None:
                        evidence_paths.add(evidence)
        rewrites[path] = kept

    for path in text_paths:
        kept = []
        for line in read_lines(path):
            if any(value and value in line for value in sensitive_values):
                text_removed += 1
            else:
                kept.append(line)
        rewrites[path] = kept

    for root in (tty_root, download_root):
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_file() and any(session in path.name for session in sessions):
                    evidence_paths.add(path.resolve(strict=False))

    existing_evidence = sorted(path for path in evidence_paths if path.is_file())
    if apply:
        for path, lines in rewrites.items():
            atomic_rewrite(path, lines)
        for path in existing_evidence:
            path.unlink()

    return {
        "mode": "apply" if apply else "dry-run",
        "json_files": len(json_paths),
        "text_files": len(text_paths),
        "operator_sessions": len(sessions),
        "json_lines_removed": json_removed,
        "text_lines_removed": text_removed,
        "evidence_files_removed": len(existing_evidence),
        "event_types": dict(sorted(event_types.items())),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--honeypot-root", type=Path, default=DEFAULT_HONEYPOT_ROOT)
    parser.add_argument("--operator-ip", action="append", required=True)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    operator_ips: set[str] = set()
    for value in args.operator_ip:
        try:
            operator_ips.add(str(ipaddress.ip_address(value)))
        except ValueError:
            print(f"ERROR: invalid operator IP: {value}")
            return 2
    if args.apply:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", "cowrie.service"], check=False,
        )
        if result.returncode == 0:
            print("ERROR: stop cowrie.service before using --apply")
            return 2
    report = purge(args.honeypot_root, operator_ips, args.apply)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
