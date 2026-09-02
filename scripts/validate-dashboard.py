#!/usr/bin/env python3
"""Validate the public Greyfield snapshot before publication."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


FORBIDDEN_RAW_KEYS = {"src_ip", "dst_ip", "src_port", "dst_port", "input", "session", "ttylog", "outfile"}
REQUIRED_SUMMARY = {
    "sessions", "unique_sources", "auth_attempts", "accepted_logins", "commands", "downloads", "attack_techniques"
}
SNAPSHOT_KEYS_V3 = {
    "schema_version", "generated_at", "window", "sensor", "summary", "hourly", "protocols", "sources",
    "credentials", "commands", "artifacts", "mitre", "recent", "data_quality", "provenance",
}
SNAPSHOT_KEYS_V4 = SNAPSHOT_KEYS_V3 | {"coverage"}
SNAPSHOT_KEYS_V5 = SNAPSHOT_KEYS_V4 | {"five_minute"}
SOURCE_KEYS = {
    "ip", "country", "country_code", "city", "latitude", "longitude", "asn", "organization", "flag",
    "sessions", "auth_attempts", "accepted", "commands", "downloads", "protocols", "first_seen", "last_seen",
}
RECENT_KEYS = {"time", "severity", "protocol", "ip", "country_code", "event", "detail"}
ARTIFACT_KEYS_V3 = {"url", "sha256", "count", "first_seen", "last_seen", "techniques", "classification"}
ARTIFACT_KEYS_V4 = {"url", "sha256", "count", "first_seen", "last_seen", "techniques", "correlation"}
CLASSIFICATION_KEYS = {"status", "label", "basis", "provider", "retrieved_at"}
CORRELATION_KEYS = {"status", "providers"}
PROVIDER_KEYS = {
    "name", "status", "label", "retrieved_at", "report_url", "tags",
    "malicious", "suspicious", "harmless", "undetected",
}
COMMAND_KEYS_V3 = {"command", "count", "families", "techniques"}
COMMAND_KEYS_V4 = COMMAND_KEYS_V3 | {"truncated"}
MITRE_KEYS_V3 = {"id", "name", "tactic", "count", "evidence"}
MITRE_KEYS_V4 = MITRE_KEYS_V3 | {"evidence_observed", "evidence_published"}
DATA_QUALITY_KEYS_V3 = {
    "events_published", "invalid_lines", "operator_events_excluded", "non_public_events_excluded",
    "content_redactions", "geo_lookups", "geo_failures", "family_lookups", "family_failures", "privacy",
}
DATA_QUALITY_KEYS_V4 = (DATA_QUALITY_KEYS_V3 - {"family_lookups", "family_failures"}) | {
    "enrichment_lookups", "enrichment_failures",
}
COVERAGE_GROUPS = {"sources", "usernames", "passwords", "commands", "artifacts"}
MAX_PUBLISHED_FILE_BYTES = 5 * 1024 * 1024
APPROVED_TECHNIQUES = {
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1053.003": ("Cron", "Persistence"),
    "T1098.004": ("SSH Authorized Keys", "Persistence"),
    "T1136.001": ("Local Account", "Persistence"),
    "T1222.002": ("Linux and Mac Permissions", "Defense Impairment"),
    "T1070.003": ("Clear Command History", "Stealth"),
    "T1070.004": ("File Deletion", "Stealth"),
    "T1496.001": ("Compute Hijacking", "Impact"),
}
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?\b")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)
LONG_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_=-]{64,}\b)(?=[A-Za-z0-9_=-]*[_=-])[A-Za-z0-9_=-]+\b")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
URL_IN_TEXT = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>]+", re.I)
LAYER_KEYS = {"name", "versions", "domain", "description", "techniques", "gradient"}
LAYER_TECHNIQUE_KEYS = {"techniqueID", "score", "comment", "enabled"}
LAYER_VERSIONS = {"attack": "19.2", "navigator": "5.1", "layer": "4.5"}
LAYER_DESCRIPTION = (
    "ATT&CK techniques mapped conservatively from Greyfield Cowrie observations; "
    "counts represent observed evidence, not attributed incidents."
)
LAYER_COLORS = ["#17131f", "#7857ff", "#ff5d73"]


def walk(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, key, child
            yield from walk(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def parse_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def require_exact_keys(value: Any, expected: set[str], path: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return False
    if set(value) != expected:
        errors.append(f"{path} contains missing or unapproved fields")
        return False
    return True


def validate_timeline(
    rows: Any, label: str, expected_count: int, bucket_minutes: int, errors: list[str],
) -> None:
    if not isinstance(rows, list):
        errors.append(f"{label} must be an array")
        return
    if len(rows) != expected_count:
        errors.append(f"{label} must contain exactly {expected_count} buckets")
    prior: datetime | None = None
    for index, row in enumerate(rows):
        path = f"{label}[{index}]"
        if not require_exact_keys(row, {"bucket", "sessions", "auth", "commands", "downloads"}, path, errors):
            continue
        bucket = parse_timestamp(row.get("bucket"))
        if bucket is None or bucket.second or bucket.microsecond or bucket.minute % bucket_minutes:
            errors.append(f"{path}.bucket must align to {bucket_minutes}-minute UTC boundaries")
        elif prior is not None and bucket - prior != timedelta(minutes=bucket_minutes):
            errors.append(f"{label} buckets must be strictly contiguous")
        prior = bucket
        for key in ("sessions", "auth", "commands", "downloads"):
            value = row.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"{path}.{key} must be a non-negative integer")


def validate_sensitive_strings(value: Any, denied_ips: set[str], label: str) -> list[str]:
    errors: list[str] = []
    for path, key, child in walk(value):
        if key.lower() in FORBIDDEN_RAW_KEYS:
            errors.append(f"raw Cowrie field is forbidden in {label} at {path}")
        if not isinstance(child, str):
            continue
        if EMAIL.search(child) or JWT.search(child) or PRIVATE_KEY.search(child) or LONG_TOKEN.search(child):
            errors.append(f"unredacted sensitive pattern in {label} at {path}")
        if any(ord(character) < 32 and character not in "\t\n\r" for character in child):
            errors.append(f"control character found in {label} at {path}")
        for match in URL_IN_TEXT.finditer(child):
            try:
                parsed = urllib.parse.urlsplit(match.group(0))
            except ValueError:
                errors.append(f"invalid embedded URL in {label} at {path}")
                continue
            if parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
                errors.append(f"unsafe embedded URL in {label} at {path}")
        for denied in denied_ips:
            if denied in child:
                errors.append(f"denied operator IP found in {label} at {path}")
    return errors


def validate(snapshot: dict[str, Any], denied_ips: set[str] | None = None) -> list[str]:
    errors: list[str] = []
    denied_ips = denied_ips or set()
    schema = snapshot.get("schema_version")
    if schema not in {"3.0", "4.0", "5.0"}:
        errors.append("schema_version must equal 3.0, 4.0, or 5.0")
    is_modern = schema in {"4.0", "5.0"}
    expected_keys = SNAPSHOT_KEYS_V5 if schema == "5.0" else SNAPSHOT_KEYS_V4 if schema == "4.0" else SNAPSHOT_KEYS_V3
    require_exact_keys(snapshot, expected_keys, "snapshot", errors)
    if parse_timestamp(snapshot.get("generated_at")) is None:
        errors.append("generated_at is missing or invalid")
    summary = snapshot.get("summary")
    if not require_exact_keys(summary, REQUIRED_SUMMARY, "summary", errors):
        summary = None
    elif any(not isinstance(summary[key], int) or isinstance(summary[key], bool) or summary[key] < 0 for key in REQUIRED_SUMMARY):
        errors.append("summary counters must be non-negative integers")

    window = snapshot.get("window")
    require_exact_keys(window, {"start", "end"}, "window", errors)
    window_data = window if isinstance(window, dict) else {}
    window_start = parse_timestamp(window_data.get("start"))
    window_end = parse_timestamp(window_data.get("end"))
    if window_start is None or window_end is None:
        errors.append("window timestamps are invalid")
    elif window_start > window_end:
        errors.append("window.start must not be later than window.end")
    require_exact_keys(
        snapshot.get("data_quality"), DATA_QUALITY_KEYS_V4 if is_modern else DATA_QUALITY_KEYS_V3,
        "data_quality", errors,
    )
    require_exact_keys(snapshot.get("provenance"), {"source", "collection", "interpretation"}, "provenance", errors)
    if is_modern:
        coverage = snapshot.get("coverage")
        if require_exact_keys(coverage, COVERAGE_GROUPS, "coverage", errors):
            for group in sorted(COVERAGE_GROUPS):
                row = coverage[group]
                if not require_exact_keys(row, {"observed", "published", "truncated"}, f"coverage.{group}", errors):
                    continue
                observed, published = row.get("observed"), row.get("published")
                if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (observed, published)):
                    errors.append(f"coverage.{group} counters must be non-negative integers")
                elif published > observed or row.get("truncated") is not (observed > published):
                    errors.append(f"coverage.{group} does not describe its publication boundary")

    validate_timeline(snapshot.get("hourly"), "hourly", 168, 60, errors)
    if schema == "5.0":
        validate_timeline(snapshot.get("five_minute"), "five_minute", 288, 5, errors)
    protocols = snapshot.get("protocols")
    if not isinstance(protocols, list):
        errors.append("protocols must be an array")
    else:
        for index, row in enumerate(protocols):
            require_exact_keys(row, {"value", "count"}, f"protocols[{index}]", errors)
    credentials = snapshot.get("credentials")
    if require_exact_keys(credentials, {"usernames", "passwords"}, "credentials", errors):
        for group in ("usernames", "passwords"):
            rows = credentials[group]
            if not isinstance(rows, list):
                errors.append(f"credentials.{group} must be an array")
                continue
            for index, row in enumerate(rows):
                require_exact_keys(row, {"value", "count"}, f"credentials.{group}[{index}]", errors)

    sources = snapshot.get("sources")
    if not isinstance(sources, list):
        errors.append("sources must be an array")
        sources = []
    published_ips: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            errors.append(f"sources[{index}] must be an object")
            continue
        require_exact_keys(source, SOURCE_KEYS, f"sources[{index}]", errors)
        address = parse_ip(source.get("ip"))
        if address is None or not address.is_global:
            errors.append(f"sources[{index}].ip must be a globally routable IP")
            continue
        normalized = str(address)
        if normalized in denied_ips:
            errors.append(f"denied operator IP found in sources[{index}]")
        if normalized in published_ips:
            errors.append(f"duplicate source IP in sources[{index}]")
        published_ips.add(normalized)

    if summary is not None:
        if is_modern:
            coverage_sources = snapshot.get("coverage", {}).get("sources", {})
            if summary.get("unique_sources") != coverage_sources.get("observed"):
                errors.append("summary.unique_sources must equal coverage.sources.observed")
            if len(sources) != coverage_sources.get("published"):
                errors.append("published sources must equal coverage.sources.published")
        elif summary.get("unique_sources") != len(sources):
            errors.append("summary.unique_sources must equal the published sources count")

    sensor = snapshot.get("sensor")
    endpoint_ip: str | None = None
    if require_exact_keys(sensor, {"name", "status", "platform", "region", "public_endpoint"}, "sensor", errors):
        if sensor.get("status") not in {"operational", "degraded"}:
            errors.append("sensor.status must be operational or degraded")
        endpoint = sensor.get("public_endpoint")
        if endpoint is not None:
            if not isinstance(endpoint, dict):
                errors.append("sensor.public_endpoint must be null or an object")
            else:
                require_exact_keys(endpoint, {"host", "services"}, "sensor.public_endpoint", errors)
                host = endpoint.get("host")
                address = parse_ip(host)
                if address is not None:
                    if not address.is_global:
                        errors.append("sensor.public_endpoint.host must be globally routable")
                    endpoint_ip = str(address)
                elif not isinstance(host, str) or not HOSTNAME.fullmatch(host):
                    errors.append("sensor.public_endpoint.host must be a global IP or hostname")
                expected_services = [
                    {"protocol": "SSH", "port": 22},
                    {"protocol": "TELNET", "port": 23},
                ]
                if endpoint.get("services") != expected_services:
                    errors.append("sensor.public_endpoint.services must expose only SSH 22 and TELNET 23")

    for index, event in enumerate(snapshot.get("recent", [])):
        if not isinstance(event, dict):
            errors.append(f"recent[{index}] must be an object")
            continue
        require_exact_keys(event, RECENT_KEYS, f"recent[{index}]", errors)
        address = parse_ip(event.get("ip"))
        if address is None or str(address) not in published_ips:
            errors.append(f"recent[{index}].ip must reference a published source")
        elif str(address) in denied_ips:
            errors.append(f"denied operator IP found in recent[{index}]")

    artifacts = snapshot.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("artifacts must be an array")
        artifacts = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"artifacts[{index}] must be an object")
            continue
        require_exact_keys(
            artifact, ARTIFACT_KEYS_V4 if is_modern else ARTIFACT_KEYS_V3,
            f"artifacts[{index}]", errors,
        )
        url = artifact.get("url")
        if url is not None and not isinstance(url, str):
            errors.append(f"artifacts[{index}].url must be null or a string")
        elif isinstance(url, str):
            try:
                parsed_url = urllib.parse.urlsplit(url)
            except ValueError:
                parsed_url = None
                errors.append(f"artifacts[{index}].url is invalid")
            if parsed_url is not None:
                if parsed_url.scheme not in {"http", "https", "ftp", "tftp"} or not parsed_url.hostname:
                    errors.append(f"artifacts[{index}].url must be an absolute transfer URL")
                if parsed_url.query or parsed_url.fragment:
                    errors.append(f"artifacts[{index}].url must not contain a query or fragment")
                if parsed_url.username is not None or parsed_url.password is not None:
                    errors.append(f"artifacts[{index}].url must not contain user information")
        sha256 = artifact.get("sha256")
        if sha256 is not None and (not isinstance(sha256, str) or not SHA256.fullmatch(sha256)):
            errors.append(f"artifacts[{index}].sha256 must be null or lowercase SHA-256")
        if artifact.get("techniques") != ["T1105"]:
            errors.append(f"artifacts[{index}].techniques must contain only T1105")
        if is_modern:
            correlation = artifact.get("correlation")
            if not require_exact_keys(correlation, CORRELATION_KEYS, f"artifacts[{index}].correlation", errors):
                continue
            if correlation.get("status") not in {"correlated", "not-found", "partial", "unavailable"}:
                errors.append(f"artifacts[{index}].correlation.status is invalid")
            providers = correlation.get("providers")
            if not isinstance(providers, list):
                errors.append(f"artifacts[{index}].correlation.providers must be an array")
                continue
            names: set[str] = set()
            for provider_index, provider_record in enumerate(providers):
                path = f"artifacts[{index}].correlation.providers[{provider_index}]"
                if not require_exact_keys(provider_record, PROVIDER_KEYS, path, errors):
                    continue
                name = provider_record.get("name")
                if name not in {"MalwareBazaar", "VirusTotal"}:
                    errors.append(f"{path}.name is not an approved provider")
                elif name in names:
                    errors.append(f"{path}.name is duplicated")
                names.add(name)
                if provider_record.get("status") not in {"correlated", "not-found", "unavailable"}:
                    errors.append(f"{path}.status is invalid")
                if parse_timestamp(provider_record.get("retrieved_at")) is None:
                    errors.append(f"{path}.retrieved_at is invalid")
                label = provider_record.get("label")
                if label is not None and (not isinstance(label, str) or not label.strip()):
                    errors.append(f"{path}.label must be null or non-empty text")
                report_url = provider_record.get("report_url")
                if report_url is not None:
                    try:
                        parsed_report = urllib.parse.urlsplit(report_url)
                    except ValueError:
                        parsed_report = None
                    approved_host = {
                        "MalwareBazaar": "bazaar.abuse.ch", "VirusTotal": "www.virustotal.com",
                    }.get(name)
                    if parsed_report is None or parsed_report.scheme != "https" or parsed_report.hostname != approved_host or parsed_report.query or parsed_report.fragment:
                        errors.append(f"{path}.report_url is not an approved provider URL")
                tags = provider_record.get("tags")
                if not isinstance(tags, list) or len(tags) > 8 or any(not isinstance(tag, str) or not tag for tag in tags):
                    errors.append(f"{path}.tags must contain at most eight strings")
                for counter in ("malicious", "suspicious", "harmless", "undetected"):
                    value = provider_record.get(counter)
                    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                        errors.append(f"{path}.{counter} must be null or a non-negative integer")
                if name == "MalwareBazaar" and any(provider_record.get(counter) is not None for counter in ("malicious", "suspicious", "harmless", "undetected")):
                    errors.append(f"{path} must not claim antivirus-engine counts")
            status = correlation.get("status")
            available = [record for record in providers if isinstance(record, dict) and record.get("status") != "unavailable"]
            if status == "unavailable" and available:
                errors.append(f"artifacts[{index}].correlation unavailable state contradicts provider results")
            if status == "correlated" and not any(record.get("status") == "correlated" for record in available):
                errors.append(f"artifacts[{index}].correlation correlated state lacks provider evidence")
            continue

        classification = artifact.get("classification")
        if not isinstance(classification, dict):
            errors.append(f"artifacts[{index}].classification must be an object")
            continue
        require_exact_keys(classification, CLASSIFICATION_KEYS, f"artifacts[{index}].classification", errors)
        status = classification.get("status")
        label = classification.get("label")
        basis = classification.get("basis")
        provider = classification.get("provider")
        retrieved_at = classification.get("retrieved_at")
        if status not in {"known", "unknown", "unavailable"}:
            errors.append(f"artifacts[{index}].classification.status is invalid")
        if status == "known":
            if not isinstance(label, str) or not label.strip():
                errors.append(f"artifacts[{index}] known classification requires a label")
            if basis not in {"third-party", "consensus"}:
                errors.append(f"artifacts[{index}] known classification requires a qualified basis")
            if not isinstance(provider, str) or not provider.strip():
                errors.append(f"artifacts[{index}] known classification requires a provider")
            if parse_timestamp(retrieved_at) is None:
                errors.append(f"artifacts[{index}] known classification requires retrieval time")
        elif status == "unknown":
            if label is not None:
                errors.append(f"artifacts[{index}] unknown classification must not have a label")
            if basis not in {"third-party", "consensus"}:
                errors.append(f"artifacts[{index}] unknown classification requires a qualified basis")
            if not isinstance(provider, str) or not provider.strip():
                errors.append(f"artifacts[{index}] unknown classification requires a provider")
            if parse_timestamp(retrieved_at) is None:
                errors.append(f"artifacts[{index}] unknown classification requires retrieval time")
        elif status == "unavailable":
            if label is not None or basis is not None:
                errors.append(f"artifacts[{index}] unavailable classification cannot claim a label or basis")
            if provider is not None and (not isinstance(provider, str) or not provider.strip()):
                errors.append(f"artifacts[{index}] unavailable classification provider is invalid")
        if retrieved_at is not None and parse_timestamp(retrieved_at) is None:
            errors.append(f"artifacts[{index}].classification.retrieved_at is invalid")

    commands = snapshot.get("commands")
    if not isinstance(commands, list):
        errors.append("commands must be an array")
        commands = []
    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            errors.append(f"commands[{index}] must be an object")
            continue
        require_exact_keys(
            command, COMMAND_KEYS_V4 if is_modern else COMMAND_KEYS_V3,
            f"commands[{index}]", errors,
        )
        if is_modern and not isinstance(command.get("truncated"), bool):
            errors.append(f"commands[{index}].truncated must be boolean")
        if not isinstance(command.get("command"), str) or not command["command"] or len(command["command"]) > 2048:
            errors.append(f"commands[{index}].command must contain at most 2048 characters")
        if not isinstance(command.get("families"), list) or not command["families"]:
            errors.append(f"commands[{index}].families must be a non-empty array")
        techniques = command.get("techniques")
        if not isinstance(techniques, list) or not techniques or any(
            not isinstance(item, str) or not TECHNIQUE_ID.fullmatch(item) for item in techniques
        ):
            errors.append(f"commands[{index}].techniques must contain ATT&CK IDs")
        elif any(item not in APPROVED_TECHNIQUES for item in techniques):
            errors.append(f"commands[{index}].techniques contains an unapproved ATT&CK mapping")

    mitre = snapshot.get("mitre")
    if not isinstance(mitre, list):
        errors.append("mitre must be an array")
        mitre = []
    mitre_ids: set[str] = set()
    for index, item in enumerate(mitre):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not TECHNIQUE_ID.fullmatch(item["id"]):
            errors.append(f"mitre[{index}] must contain a valid ATT&CK ID")
            continue
        require_exact_keys(item, MITRE_KEYS_V4 if is_modern else MITRE_KEYS_V3, f"mitre[{index}]", errors)
        approved = APPROVED_TECHNIQUES.get(item["id"])
        if approved is None:
            if item["id"] == "T1078":
                errors.append("T1078 must not be inferred from Cowrie decoy login acceptance")
            else:
                errors.append(f"mitre[{index}] contains an unapproved ATT&CK mapping")
        elif (item.get("name"), item.get("tactic")) != approved:
            errors.append(f"mitre[{index}] ATT&CK name or tactic does not match the approved mapping")
        if not isinstance(item.get("count"), int) or isinstance(item.get("count"), bool) or item["count"] < 1:
            errors.append(f"mitre[{index}].count must be a positive integer")
        evidence = item.get("evidence")
        if is_modern:
            if not isinstance(evidence, list) or not evidence or len(evidence) > 25:
                errors.append(f"mitre[{index}].evidence must contain one to 25 reviewed entries")
                evidence = []
            for evidence_index, evidence_item in enumerate(evidence):
                path = f"mitre[{index}].evidence[{evidence_index}]"
                if not require_exact_keys(evidence_item, {"value", "count", "truncated"}, path, errors):
                    continue
                if not isinstance(evidence_item.get("value"), str) or not evidence_item["value"] or len(evidence_item["value"]) > 2048:
                    errors.append(f"{path}.value must contain at most 2048 characters")
                if not isinstance(evidence_item.get("count"), int) or isinstance(evidence_item.get("count"), bool) or evidence_item["count"] < 1:
                    errors.append(f"{path}.count must be a positive integer")
                if not isinstance(evidence_item.get("truncated"), bool):
                    errors.append(f"{path}.truncated must be boolean")
            observed = item.get("evidence_observed")
            published = item.get("evidence_published")
            if not isinstance(observed, int) or isinstance(observed, bool) or observed < len(evidence):
                errors.append(f"mitre[{index}].evidence_observed is invalid")
            if published != len(evidence):
                errors.append(f"mitre[{index}].evidence_published must equal evidence length")
        elif not isinstance(evidence, list) or not evidence or len(evidence) > 3 or any(
            not isinstance(value, str) or not value for value in evidence
        ):
            errors.append(f"mitre[{index}].evidence must contain one to three strings")
        if item["id"] in mitre_ids:
            errors.append(f"duplicate ATT&CK mapping at mitre[{index}]")
        mitre_ids.add(item["id"])
    if summary is not None and summary.get("attack_techniques") != len(mitre_ids):
        errors.append("summary.attack_techniques must equal unique mapped techniques")
    referenced_ids = {
        technique for command in commands if isinstance(command, dict)
        for technique in command.get("techniques", []) if isinstance(technique, str)
    }
    if artifacts:
        referenced_ids.add("T1105")
    if not referenced_ids.issubset(mitre_ids):
        errors.append("command or artifact ATT&CK mappings are missing from the mitre summary")

    for path, key, value in walk(snapshot):
        address = parse_ip(value)
        approved_source_ip = path.endswith(".ip") and (path.startswith("$.sources[") or path.startswith("$.recent["))
        approved_endpoint_ip = path == "$.sensor.public_endpoint.host" and endpoint_ip == str(address)
        if address is not None and not (approved_source_ip or approved_endpoint_ip):
            errors.append(f"IP address found outside an approved evidence field at {path}")
    errors.extend(validate_sensitive_strings(snapshot, denied_ips, "snapshot"))

    encoded = json.dumps(snapshot, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 5_000_000:
        errors.append("snapshot exceeds the 5 MB publication limit")
    return errors


def validate_layer(
    layer: dict[str, Any], snapshot: dict[str, Any], denied_ips: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    denied_ips = denied_ips or set()
    if set(layer) != LAYER_KEYS:
        errors.append("Navigator layer must contain only the approved top-level fields")
    if layer.get("name") != "Greyfield observed techniques":
        errors.append("Navigator layer name is invalid")
    if layer.get("versions") != LAYER_VERSIONS:
        errors.append("Navigator layer versions are invalid")
    if layer.get("domain") != "enterprise-attack":
        errors.append("Navigator layer domain must be enterprise-attack")
    if layer.get("description") != LAYER_DESCRIPTION:
        errors.append("Navigator layer description is invalid")

    snapshot_items = snapshot.get("mitre") if isinstance(snapshot.get("mitre"), list) else []
    expected: dict[str, dict[str, Any]] = {
        item["id"]: item for item in snapshot_items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    techniques = layer.get("techniques")
    if not isinstance(techniques, list):
        errors.append("Navigator layer techniques must be an array")
        techniques = []
    seen: set[str] = set()
    for index, item in enumerate(techniques):
        if not isinstance(item, dict):
            errors.append(f"Navigator layer techniques[{index}] must be an object")
            continue
        if set(item) != LAYER_TECHNIQUE_KEYS:
            errors.append(f"Navigator layer techniques[{index}] contains unapproved fields")
        technique_id = item.get("techniqueID")
        if not isinstance(technique_id, str) or not TECHNIQUE_ID.fullmatch(technique_id):
            errors.append(f"Navigator layer techniques[{index}].techniqueID is invalid")
            continue
        if technique_id in seen:
            errors.append(f"duplicate Navigator technique {technique_id}")
        seen.add(technique_id)
        source = expected.get(technique_id)
        if source is None:
            errors.append(f"Navigator technique {technique_id} is absent from metrics.json")
            continue
        score = item.get("score")
        if not isinstance(score, int) or isinstance(score, bool) or score < 1:
            errors.append(f"Navigator technique {technique_id} score must be a positive integer")
        if score != source.get("count"):
            errors.append(f"Navigator technique {technique_id} score does not match metrics.json")
        if item.get("enabled") is not True:
            errors.append(f"Navigator technique {technique_id} must be enabled")
        evidence = source.get("evidence") if isinstance(source.get("evidence"), list) else []
        if snapshot.get("schema_version") in {"4.0", "5.0"}:
            expected_comment = "; ".join(
                str(value.get("value")) for value in evidence[:2] if isinstance(value, dict)
            )
        else:
            expected_comment = "; ".join(str(value) for value in evidence[:2])
        if item.get("comment") != expected_comment:
            errors.append(f"Navigator technique {technique_id} comment does not match metrics.json")
    if seen != set(expected):
        errors.append("Navigator layer technique set does not match metrics.json")

    maximum = max((item.get("count", 0) for item in expected.values()), default=1)
    expected_gradient = {"colors": LAYER_COLORS, "minValue": 0, "maxValue": maximum}
    if layer.get("gradient") != expected_gradient:
        errors.append("Navigator layer gradient does not match metrics.json")
    errors.extend(validate_sensitive_strings(layer, denied_ips, "Navigator layer"))
    if len(json.dumps(layer, separators=(",", ":")).encode("utf-8")) > 1_000_000:
        errors.append("Navigator layer exceeds the 1 MB publication limit")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--layer", type=Path)
    parser.add_argument("--deny-ip", action="append", default=[])
    parser.add_argument("--max-age-hours", type=float)
    args = parser.parse_args()
    for label, path in (("snapshot", args.snapshot), ("Navigator layer", args.layer)):
        if path is None:
            continue
        try:
            if path.stat().st_size > MAX_PUBLISHED_FILE_BYTES:
                print(f"ERROR: {label} exceeds the 5 MB publication boundary", file=sys.stderr)
                return 1
        except OSError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if not isinstance(snapshot, dict):
        print("ERROR: snapshot root must be an object", file=sys.stderr)
        return 1
    denied: set[str] = set()
    for value in args.deny_ip:
        try:
            denied.add(str(ipaddress.ip_address(value)))
        except ValueError:
            print(f"ERROR: invalid denied IP: {value}", file=sys.stderr)
            return 1
    errors = validate(snapshot, denied)
    if args.layer is not None:
        try:
            layer = json.loads(args.layer.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 1
        if not isinstance(layer, dict):
            errors.append("Navigator layer root must be an object")
        else:
            errors.extend(validate_layer(layer, snapshot, denied))
    if args.max_age_hours is not None:
        generated_at = parse_timestamp(snapshot.get("generated_at"))
        if generated_at is None:
            errors.append("generated_at is missing or invalid")
        elif generated_at < datetime.now(timezone.utc) - timedelta(hours=max(0, args.max_age_hours)):
            errors.append(f"snapshot is older than {args.max_age_hours:g} hours")
        elif generated_at > datetime.now(timezone.utc) + timedelta(minutes=10):
            errors.append("generated_at is more than 10 minutes in the future")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.layer is None:
        print(f"Dashboard snapshot validated: {args.snapshot}")
    else:
        print(f"Dashboard snapshot and Navigator layer validated: {args.snapshot}, {args.layer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
