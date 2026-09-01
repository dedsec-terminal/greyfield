#!/usr/bin/env python3
"""Build a public Greyfield threat-intelligence snapshot from Cowrie JSON.

Operator addresses are removed before aggregation. Public attacker evidence is
kept concrete: routable source IPs, attempted credentials, commands, artifact
URLs, and hashes may be published after control-character and secret-pattern
redaction. The browser renders these values as text, never as HTML.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "4.0"
DEFAULT_LOG = Path("/home/cowrie/honeypot/var/log/cowrie/cowrie.json")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
WHITESPACE = re.compile(r"\s+")
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{10,})?\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)
LONG_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_=-]{64,}\b)(?=[A-Za-z0-9_=-]*[_=-])[A-Za-z0-9_=-]+\b")
SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
URL_IN_TEXT = re.compile(r"\b(?:https?|ftp|tftp)://[^\s'\"<>]+", re.I)
ENRICHMENT_CACHE_SCHEMA = "2.0"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"
PUBLIC_LIMITS = {
    "sources": 500,
    "usernames": 250,
    "passwords": 250,
    "commands": 500,
    "artifacts": 250,
    "technique_evidence": 25,
}
COMMAND_LIMIT = 2048

TECHNIQUES = {
    "brute_force": ("T1110.001", "Password Guessing", "Credential Access"),
    "shell": ("T1059.004", "Unix Shell", "Execution"),
    "system_info": ("T1082", "System Information Discovery", "Discovery"),
    "network_info": ("T1016", "System Network Configuration Discovery", "Discovery"),
    "process_info": ("T1057", "Process Discovery", "Discovery"),
    "file_discovery": ("T1083", "File and Directory Discovery", "Discovery"),
    "tool_transfer": ("T1105", "Ingress Tool Transfer", "Command and Control"),
    "scheduled_task": ("T1053.003", "Cron", "Persistence"),
    "account_manipulation": ("T1098.004", "SSH Authorized Keys", "Persistence"),
    "local_account": ("T1136.001", "Local Account", "Persistence"),
    "permission_change": ("T1222.002", "Linux and Mac Permissions", "Defense Impairment"),
    "clear_history": ("T1070.003", "Clear Command History", "Stealth"),
    "file_deletion": ("T1070.004", "File Deletion", "Stealth"),
    "resource_hijacking": ("T1496.001", "Compute Hijacking", "Impact"),
}

COMMAND_RULES = (
    ("Payload transfer", "tool_transfer", re.compile(r"\b(?:wget|curl|ftp|tftp|scp)\b", re.I)),
    ("System discovery", "system_info", re.compile(r"\b(?:uname|hostname|whoami|id|lscpu|free|df)\b", re.I)),
    ("Network discovery", "network_info", re.compile(r"\b(?:ifconfig|ip\s|route|netstat|ss\s|arp)\b", re.I)),
    ("Process discovery", "process_info", re.compile(r"\b(?:ps|top|pgrep|pidof)\b", re.I)),
    ("File discovery", "file_discovery", re.compile(r"\b(?:find|ls|pwd|cat)\b", re.I)),
    ("Scheduled persistence", "scheduled_task", re.compile(r"\b(?:cron|crontab|at\s)\b", re.I)),
    ("SSH key persistence", "account_manipulation", re.compile(r"authorized_keys", re.I)),
    ("Local account creation", "local_account", re.compile(r"\b(?:useradd|adduser)\b", re.I)),
    ("Permission change", "permission_change", re.compile(r"\b(?:chmod|chown|chattr)\b", re.I)),
    ("Command-history removal", "clear_history", re.compile(r"history\s+-c|(?:^|[;&|]\s*)unset\s+HISTFILE\b", re.I)),
    ("File deletion", "file_deletion", re.compile(r"\b(?:rm|shred|unlink)\s", re.I)),
    ("Resource hijacking", "resource_hijacking", re.compile(r"\b(?:xmrig|miner|stratum\+tcp)\b", re.I)),
    ("Shell execution", "shell", re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?(?:/bin/)?(?:bash|sh|dash|zsh)\b|\b(?:python|perl|php)\b", re.I)),
)

EVENT_LABELS = {
    "cowrie.session.connect": ("Connection opened", "info"),
    "cowrie.login.failed": ("Credential rejected", "medium"),
    "cowrie.login.success": ("Decoy access granted", "high"),
    "cowrie.command.input": ("Command executed", "high"),
    "cowrie.session.file_download": ("Artifact retrieved", "critical"),
}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean_evidence(
    value: Any, limit: int = 180, sensitive_values: Iterable[str] = ()
) -> tuple[str, int]:
    text = CONTROL_CHARS.sub(" ", str(value or ""))
    text = WHITESPACE.sub(" ", text).strip()
    redactions = 0
    def strip_query(match: re.Match[str]) -> str:
        nonlocal redactions
        candidate = match.group(0)
        try:
            parsed = urllib.parse.urlsplit(candidate)
            port = parsed.port
        except ValueError:
            return candidate
        hostname = parsed.hostname
        if not hostname:
            return candidate
        host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = f"{host}:{port}" if port is not None else host
        if parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
            redactions += 1
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))

    text = URL_IN_TEXT.sub(strip_query, text)
    for pattern in (EMAIL, JWT, PRIVATE_KEY, LONG_TOKEN):
        text, count = pattern.subn("[redacted]", text)
        redactions += count
    for sensitive in sorted(set(sensitive_values), key=len, reverse=True):
        if sensitive:
            text, count = re.subn(re.escape(sensitive), "[redacted-ip]", text)
            redactions += count
    return (text[:limit] or "(empty)"), redactions


def clean_command(value: Any, sensitive_values: Iterable[str] = ()) -> tuple[str, int, bool]:
    text, redactions = clean_evidence(value, COMMAND_LIMIT + 1, sensitive_values)
    return text[:COMMAND_LIMIT], redactions, len(text) > COMMAND_LIMIT


def clean_url(value: Any, sensitive_values: Iterable[str] = ()) -> tuple[str | None, int]:
    text, redactions = clean_evidence(value, 512, sensitive_values)
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return None, redactions + 1
    try:
        port = parsed.port
    except ValueError:
        return None, redactions + 1
    hostname = parsed.hostname
    if (
        parsed.scheme.lower() not in {"http", "https", "ftp", "tftp"}
        or not hostname
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or any(character.isspace() for character in hostname)
    ):
        return None, redactions + 1
    if parsed.query or parsed.fragment:
        redactions += 1
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))[:220], redactions


def clean_sha256(value: Any) -> str | None:
    text = str(value or "").strip()
    return text.lower() if SHA256.fullmatch(text) else None


def clean_public_endpoint(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text if HOSTNAME.fullmatch(text) else None
    return str(address) if address.is_global else None


def valid_public_ip(value: Any) -> str | None:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return str(address) if address.is_global else None


def load_events(log_path: Path) -> tuple[list[dict[str, Any]], int]:
    events: list[dict[str, Any]] = []
    invalid = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue
            if isinstance(item, dict):
                events.append(item)
            else:
                invalid += 1
    return events, invalid


def classify_command(command: str) -> tuple[list[str], list[str]]:
    matches = [(family, technique) for family, technique, pattern in COMMAND_RULES if pattern.search(command)]
    if not matches:
        matches = [("Other shell activity", "shell")]
    families = list(dict.fromkeys(family for family, _ in matches))
    techniques = list(dict.fromkeys(technique for _, technique in matches))
    return families, techniques


def top_rows(counter: Counter[str], limit: int) -> list[dict[str, Any]]:
    return [{"value": label, "count": count} for label, count in counter.most_common(limit)]


def coverage_row(observed: int, published: int) -> dict[str, Any]:
    return {"observed": observed, "published": published, "truncated": observed > published}


def load_geo_cache(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def lookup_geo(address: str) -> dict[str, Any]:
    fields = "success,country,country_code,city,latitude,longitude,connection,flag"
    url = f"https://ipwho.is/{urllib.parse.quote(address)}?fields={urllib.parse.quote(fields)}"
    request = urllib.request.Request(url, headers={"User-Agent": "Greyfield/1.0 threat-research exporter"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict) or not data.get("success"):
        return {}
    connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
    flag = data.get("flag") if isinstance(data.get("flag"), dict) else {}
    return {
        "country": str(data.get("country") or "Unknown")[:64],
        "country_code": str(data.get("country_code") or "ZZ")[:2].upper(),
        "city": str(data.get("city") or "Unknown")[:64],
        "latitude": round(float(data.get("latitude") or 0), 4),
        "longitude": round(float(data.get("longitude") or 0), 4),
        "asn": int(connection.get("asn") or 0),
        "organization": str(connection.get("org") or connection.get("isp") or "Unknown")[:96],
        "flag": str(flag.get("emoji") or "")[:8],
        "fetched_at": iso_z(datetime.now(timezone.utc)),
    }


def enrich_sources(
    addresses: list[str], cache_path: Path | None, excluded_ips: set[str], limit: int
) -> tuple[dict[str, dict[str, Any]], int, int]:
    if cache_path is None:
        return {}, 0, 0
    cache = load_geo_cache(cache_path)
    for excluded in excluded_ips:
        cache.pop(excluded, None)
    lookups = failures = 0
    for address in addresses:
        if address in cache or lookups >= limit:
            continue
        lookups += 1
        result = lookup_geo(address)
        if result:
            cache[address] = result
        else:
            failures += 1
    if cache_path is not None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
        try:
            cache_path.chmod(0o600)
        except OSError:
            pass
    return cache, lookups, failures


def load_enrichment_cache(path: Path | None) -> dict[str, Any]:
    empty = {"schema_version": ENRICHMENT_CACHE_SCHEMA, "entries": {}, "retries": {}}
    if path is None or not path.exists():
        return empty
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(payload, dict) or payload.get("schema_version") != ENRICHMENT_CACHE_SCHEMA:
        return empty
    if not isinstance(payload.get("entries"), dict) or not isinstance(payload.get("retries"), dict):
        return empty
    return payload


def save_enrichment_cache(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def read_auth_key(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def provider_record(
    name: str, status: str, retrieved_at: str, *, label: str | None = None,
    report_url: str | None = None, tags: list[str] | None = None,
    malicious: int | None = None, suspicious: int | None = None,
    harmless: int | None = None, undetected: int | None = None,
) -> dict[str, Any]:
    return {
        "name": name, "status": status, "label": label, "retrieved_at": retrieved_at,
        "report_url": report_url, "tags": tags or [], "malicious": malicious,
        "suspicious": suspicious, "harmless": harmless, "undetected": undetected,
    }


def lookup_malwarebazaar(sha256: str, auth_key: str) -> tuple[dict[str, Any], bool]:
    """Query MalwareBazaar by hash only; never submit or retrieve a file."""
    encoded = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode("ascii")
    request = urllib.request.Request(
        MALWAREBAZAAR_URL,
        data=encoded,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Greyfield/1.0 hash-correlation",
        },
        method="POST",
    )
    retrieved_at = iso_z(datetime.now(timezone.utc))
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return provider_record("MalwareBazaar", "unavailable", retrieved_at), True
    if not isinstance(payload, dict):
        return provider_record("MalwareBazaar", "unavailable", retrieved_at), True
    status = str(payload.get("query_status") or "")
    if status in {"hash_not_found", "no_results"}:
        return provider_record("MalwareBazaar", "not-found", retrieved_at), False
    rows = payload.get("data")
    if status == "ok" and isinstance(rows, list) and rows and isinstance(rows[0], dict):
        label, _ = clean_evidence(rows[0].get("signature"), 80)
        tags = []
        for value in rows[0].get("tags") or []:
            cleaned, _ = clean_evidence(value, 40)
            if cleaned != "(empty)" and cleaned not in tags:
                tags.append(cleaned)
            if len(tags) == 8:
                break
        return provider_record(
            "MalwareBazaar", "correlated", retrieved_at,
            label=None if label == "(empty)" else label,
            report_url=f"https://bazaar.abuse.ch/sample/{sha256}/", tags=tags,
        ), False
    return provider_record("MalwareBazaar", "unavailable", retrieved_at), True


def lookup_virustotal(sha256: str, api_key: str) -> tuple[dict[str, Any], bool]:
    """Retrieve an existing VirusTotal hash report; never submit or rescan a file."""
    retrieved_at = iso_z(datetime.now(timezone.utc))
    request = urllib.request.Request(
        VIRUSTOTAL_URL + sha256,
        headers={"x-apikey": api_key, "User-Agent": "Greyfield/1.0 hash-correlation"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return provider_record("VirusTotal", "not-found", retrieved_at), False
        return provider_record("VirusTotal", "unavailable", retrieved_at), True
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return provider_record("VirusTotal", "unavailable", retrieved_at), True
    data = payload.get("data") if isinstance(payload, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        return provider_record("VirusTotal", "unavailable", retrieved_at), True
    stats = attributes.get("last_analysis_stats")
    stats = stats if isinstance(stats, dict) else {}
    classification = attributes.get("popular_threat_classification")
    classification = classification if isinstance(classification, dict) else {}
    label, _ = clean_evidence(classification.get("suggested_threat_label"), 80)
    tags = []
    for value in attributes.get("tags") or []:
        cleaned, _ = clean_evidence(value, 40)
        if cleaned != "(empty)" and cleaned not in tags:
            tags.append(cleaned)
        if len(tags) == 8:
            break
    return provider_record(
        "VirusTotal", "correlated", retrieved_at,
        label=None if label == "(empty)" else label,
        report_url=f"https://www.virustotal.com/gui/file/{sha256}", tags=tags,
        malicious=int(stats.get("malicious") or 0), suspicious=int(stats.get("suspicious") or 0),
        harmless=int(stats.get("harmless") or 0), undetected=int(stats.get("undetected") or 0),
    ), False


def unavailable_correlation() -> dict[str, Any]:
    return {"status": "unavailable", "providers": []}


def correlation_status(records: list[dict[str, Any]], configured_count: int) -> str:
    if not records:
        return "unavailable"
    available = [record for record in records if record.get("status") != "unavailable"]
    if not available:
        return "unavailable"
    if any(record.get("status") == "correlated" for record in available):
        return "correlated" if len(available) == configured_count else "partial"
    return "not-found" if len(available) == configured_count else "partial"


def enrich_hashes(
    hashes: Iterable[str], cache_path: Path | None, providers: list[str],
    malwarebazaar_key_path: Path | None, virustotal_key_path: Path | None,
    limit: int,
) -> tuple[dict[str, dict[str, Any]], int, int]:
    payload = load_enrichment_cache(cache_path)
    entries: dict[str, Any] = payload["entries"]
    retries: dict[str, Any] = payload["retries"]
    normalized_hashes = list(dict.fromkeys(item for item in hashes if SHA256.fullmatch(item)))
    lookups = failures = 0
    keys = {
        "malwarebazaar": read_auth_key(malwarebazaar_key_path),
        "virustotal": read_auth_key(virustotal_key_path),
    }
    now = datetime.now(timezone.utc)
    for provider in providers:
        key = keys.get(provider)
        if not key or cache_path is None:
            continue
        provider_lookups = 0
        for sha256 in normalized_hashes:
            hash_entries = entries.setdefault(sha256, {})
            if provider in hash_entries or provider_lookups >= limit:
                continue
            retry = retries.get(sha256, {}).get(provider, {})
            next_retry = parse_timestamp(retry.get("next_retry")) if isinstance(retry, dict) else None
            if next_retry is not None and next_retry > now:
                continue
            if provider == "virustotal" and provider_lookups:
                time.sleep(16)
            provider_lookups += 1
            lookups += 1
            result, transient = (
                lookup_malwarebazaar(sha256, key) if provider == "malwarebazaar"
                else lookup_virustotal(sha256, key)
            )
            if transient:
                failures += 1
                prior_attempts = int(retry.get("attempts") or 0) if isinstance(retry, dict) else 0
                attempts = min(prior_attempts + 1, 6)
                delay_hours = min(24, 2 ** (attempts - 1))
                retries.setdefault(sha256, {})[provider] = {
                    "attempts": attempts, "next_retry": iso_z(now + timedelta(hours=delay_hours)),
                }
            else:
                hash_entries[provider] = result
                if sha256 in retries and provider in retries[sha256]:
                    del retries[sha256][provider]
        save_enrichment_cache(cache_path, payload)

    output: dict[str, dict[str, Any]] = {}
    for sha256 in normalized_hashes:
        cached = entries.get(sha256) if isinstance(entries.get(sha256), dict) else {}
        records = [cached[provider] for provider in providers if isinstance(cached.get(provider), dict)]
        output[sha256] = {"status": correlation_status(records, len(providers)), "providers": records}
    return output, lookups, failures


def build_hourly(events: Iterable[dict[str, Any]], end: datetime) -> list[dict[str, Any]]:
    end_hour = end.replace(minute=0, second=0, microsecond=0)
    start_hour = end_hour - timedelta(hours=167)
    buckets: dict[datetime, Counter[str]] = defaultdict(Counter)
    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))
        if timestamp is None or not start_hour <= timestamp < end_hour + timedelta(hours=1):
            continue
        bucket = timestamp.replace(minute=0, second=0, microsecond=0)
        event_id = str(event.get("eventid", ""))
        if event_id == "cowrie.session.connect":
            buckets[bucket]["sessions"] += 1
        elif event_id in {"cowrie.login.failed", "cowrie.login.success"}:
            buckets[bucket]["auth"] += 1
        elif event_id == "cowrie.command.input":
            buckets[bucket]["commands"] += 1
        elif event_id == "cowrie.session.file_download":
            buckets[bucket]["downloads"] += 1
    return [
        {
            "bucket": iso_z(start_hour + timedelta(hours=offset)),
            "sessions": buckets[start_hour + timedelta(hours=offset)]["sessions"],
            "auth": buckets[start_hour + timedelta(hours=offset)]["auth"],
            "commands": buckets[start_hour + timedelta(hours=offset)]["commands"],
            "downloads": buckets[start_hour + timedelta(hours=offset)]["downloads"],
        }
        for offset in range(168)
    ]


def build_snapshot(
    events: list[dict[str, Any]], invalid_lines: int, excluded_ips: set[str], sensor_name: str,
    region: str, sensor_status: str = "operational", geo_cache_path: Path | None = None,
    geo_limit: int = 40, enrichment_cache_path: Path | None = None,
    enrichment_providers: list[str] | None = None,
    malwarebazaar_key_path: Path | None = None, virustotal_key_path: Path | None = None,
    provider_limit: int = 3,
    public_endpoint: str | None = None,
) -> dict[str, Any]:
    enrichment_providers = enrichment_providers or []
    filtered: list[dict[str, Any]] = []
    excluded_count = non_public_count = 0
    for original in events:
        raw_address = str(original.get("src_ip") or "")
        if raw_address in excluded_ips:
            excluded_count += 1
            continue
        address = valid_public_ip(raw_address)
        if not address:
            non_public_count += 1
            continue
        event = dict(original)
        event["_public_ip"] = address
        filtered.append(event)

    timestamps = [stamp for event in filtered if (stamp := parse_timestamp(event.get("timestamp")))]
    now = datetime.now(timezone.utc)
    window_start = min(timestamps) if timestamps else now
    window_end = max(timestamps) if timestamps else now
    source_stats: dict[str, dict[str, Any]] = {}
    usernames: Counter[str] = Counter()
    passwords: Counter[str] = Counter()
    command_counts: Counter[str] = Counter()
    command_meta: dict[str, tuple[list[str], list[str], bool]] = {}
    artifact_counts: Counter[tuple[str, str | None]] = Counter()
    artifact_times: dict[tuple[str, str | None], list[datetime]] = defaultdict(list)
    auth_evidence: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    protocols: Counter[str] = Counter()
    technique_counts: Counter[str] = Counter()
    technique_evidence: dict[str, Counter[str]] = defaultdict(Counter)
    content_redactions = 0

    for event in filtered:
        address = event["_public_ip"]
        timestamp = parse_timestamp(event.get("timestamp")) or now
        stats = source_stats.setdefault(address, {
            "ip": address, "sessions": 0, "auth_attempts": 0, "accepted": 0,
            "commands": 0, "downloads": 0, "protocols": Counter(),
            "first_seen": timestamp, "last_seen": timestamp,
        })
        stats["first_seen"] = min(stats["first_seen"], timestamp)
        stats["last_seen"] = max(stats["last_seen"], timestamp)
        protocol = str(event.get("protocol") or "unknown").upper()
        protocol = protocol if protocol in {"SSH", "TELNET"} else "OTHER"
        stats["protocols"][protocol] += 1
        event_id = str(event.get("eventid") or "")

        if event_id == "cowrie.session.connect":
            stats["sessions"] += 1
            protocols[protocol] += 1
        elif event_id in {"cowrie.login.failed", "cowrie.login.success"}:
            stats["auth_attempts"] += 1
            username, redacted = clean_evidence(event.get("username"), 48, excluded_ips)
            content_redactions += redacted
            password, redacted = clean_evidence(event.get("password"), 64, excluded_ips)
            content_redactions += redacted
            usernames[username] += 1
            passwords[password] += 1
            actor = (address, str(event.get("session") or address))
            auth_evidence[actor].append((username, password))
            if event_id == "cowrie.login.success":
                stats["accepted"] += 1
        elif event_id == "cowrie.command.input":
            stats["commands"] += 1
            command, redacted, truncated = clean_command(event.get("input"), excluded_ips)
            content_redactions += redacted
            families, techniques = classify_command(command)
            command_counts[command] += 1
            command_meta[command] = (families, techniques, truncated)
            for technique in techniques:
                technique_counts[technique] += 1
                technique_evidence[technique][command] += 1
        elif event_id == "cowrie.session.file_download":
            stats["downloads"] += 1
            url, redacted = clean_url(event.get("url"), excluded_ips)
            content_redactions += redacted
            sha256 = clean_sha256(event.get("shasum"))
            key = (url, sha256)
            artifact_counts[key] += 1
            artifact_times[key].append(timestamp)
            technique_counts["tool_transfer"] += 1
            technique_evidence["tool_transfer"][url or "Malformed transfer reference withheld"] += 1

    for attempts in auth_evidence.values():
        distinct = list(dict.fromkeys(attempts))
        if len(distinct) < 2:
            continue
        technique_counts["brute_force"] += len(attempts)
        for username, password in distinct:
            technique_evidence["brute_force"][f"{username} / {password}"] += 1

    ranked_addresses = sorted(source_stats, key=lambda item: (
        source_stats[item]["sessions"] + source_stats[item]["auth_attempts"] + source_stats[item]["commands"],
        source_stats[item]["last_seen"],
    ), reverse=True)
    published_addresses = ranked_addresses[:PUBLIC_LIMITS["sources"]]
    geo_cache, geo_lookups, geo_failures = enrich_sources(
        published_addresses, geo_cache_path, excluded_ips, geo_limit,
    )

    sources = []
    for address in published_addresses:
        stats, geo = source_stats[address], geo_cache.get(address, {})
        sources.append({
            "ip": address, "country": geo.get("country", "Unknown"),
            "country_code": geo.get("country_code", "ZZ"), "city": geo.get("city", "Unknown"),
            "latitude": geo.get("latitude"), "longitude": geo.get("longitude"), "asn": geo.get("asn"),
            "organization": geo.get("organization", "Unresolved network"), "flag": geo.get("flag", ""),
            "sessions": stats["sessions"], "auth_attempts": stats["auth_attempts"],
            "accepted": stats["accepted"], "commands": stats["commands"], "downloads": stats["downloads"],
            "protocols": sorted(stats["protocols"]), "first_seen": iso_z(stats["first_seen"]),
            "last_seen": iso_z(stats["last_seen"]),
        })

    commands = []
    for command, count in command_counts.most_common(PUBLIC_LIMITS["commands"]):
        families, techniques, truncated = command_meta[command]
        commands.append({
            "command": command, "count": count, "families": families,
            "techniques": [TECHNIQUES[technique][0] for technique in techniques],
            "truncated": truncated,
        })

    correlation_map, enrichment_lookups, enrichment_failures = enrich_hashes(
        (sha256 for _, sha256 in artifact_counts if sha256), enrichment_cache_path,
        enrichment_providers, malwarebazaar_key_path, virustotal_key_path,
        max(0, provider_limit),
    )
    artifacts = []
    for (url, sha256), count in artifact_counts.most_common(PUBLIC_LIMITS["artifacts"]):
        times = artifact_times[(url, sha256)]
        artifacts.append({
            "url": url, "sha256": sha256, "count": count,
            "first_seen": iso_z(min(times)), "last_seen": iso_z(max(times)),
            "techniques": [TECHNIQUES["tool_transfer"][0]],
            "correlation": correlation_map.get(sha256, unavailable_correlation()) if sha256
            else unavailable_correlation(),
        })

    mitre = []
    for key, count in technique_counts.most_common():
        if count:
            technique_id, name, tactic = TECHNIQUES[key]
            observed_evidence = technique_evidence[key]
            evidence = [
                {"value": value[:COMMAND_LIMIT], "count": evidence_count,
                 "truncated": len(value) > COMMAND_LIMIT}
                for value, evidence_count in observed_evidence.most_common(PUBLIC_LIMITS["technique_evidence"])
            ]
            mitre.append({
                "id": technique_id, "name": name, "tactic": tactic, "count": count,
                "evidence": evidence, "evidence_observed": len(observed_evidence),
                "evidence_published": len(evidence),
            })

    recent = []
    for event in reversed(filtered):
        event_id = str(event.get("eventid") or "")
        if event_id not in EVENT_LABELS:
            continue
        label, severity = EVENT_LABELS[event_id]
        detail = ""
        if event_id in {"cowrie.login.failed", "cowrie.login.success"}:
            username, _ = clean_evidence(event.get("username"), 48, excluded_ips)
            password, _ = clean_evidence(event.get("password"), 64, excluded_ips)
            detail = f"{username} / {password}"
        elif event_id == "cowrie.command.input":
            detail, _ = clean_evidence(event.get("input"), 512, excluded_ips)
        elif event_id == "cowrie.session.file_download":
            detail, _ = clean_url(event.get("url"), excluded_ips)
            detail = detail or "Malformed transfer reference withheld"
        address = event["_public_ip"]
        recent.append({
            "time": iso_z(parse_timestamp(event.get("timestamp")) or now), "severity": severity,
            "protocol": str(event.get("protocol") or "unknown").upper()[:12], "ip": address,
            "country_code": geo_cache.get(address, {}).get("country_code", "ZZ"), "event": label, "detail": detail,
        })
        if len(recent) == 40:
            break

    endpoint = clean_public_endpoint(public_endpoint)
    sensor = {
        "name": clean_evidence(sensor_name, 48)[0], "status": sensor_status,
        "platform": "Cowrie 3.0.13", "region": clean_evidence(region, 32)[0],
        "public_endpoint": None,
    }
    if endpoint:
        sensor["public_endpoint"] = {
            "host": endpoint,
            "services": [{"protocol": "SSH", "port": 22}, {"protocol": "TELNET", "port": 23}],
        }

    return {
        "schema_version": SCHEMA_VERSION, "generated_at": iso_z(now),
        "window": {"start": iso_z(window_start), "end": iso_z(window_end)},
        "sensor": sensor,
        "summary": {
            "sessions": sum(item["sessions"] for item in source_stats.values()), "unique_sources": len(source_stats),
            "auth_attempts": sum(item["auth_attempts"] for item in source_stats.values()),
            "accepted_logins": sum(item["accepted"] for item in source_stats.values()),
            "commands": sum(command_counts.values()), "downloads": sum(artifact_counts.values()),
            "attack_techniques": len(mitre),
        },
        "hourly": build_hourly(filtered, window_end), "protocols": top_rows(protocols, 3), "sources": sources,
        "credentials": {
            "usernames": top_rows(usernames, PUBLIC_LIMITS["usernames"]),
            "passwords": top_rows(passwords, PUBLIC_LIMITS["passwords"]),
        },
        "commands": commands, "artifacts": artifacts, "mitre": mitre, "recent": recent,
        "coverage": {
            "sources": coverage_row(len(ranked_addresses), len(sources)),
            "usernames": coverage_row(len(usernames), min(len(usernames), PUBLIC_LIMITS["usernames"])),
            "passwords": coverage_row(len(passwords), min(len(passwords), PUBLIC_LIMITS["passwords"])),
            "commands": coverage_row(len(command_counts), len(commands)),
            "artifacts": coverage_row(len(artifact_counts), len(artifacts)),
        },
        "data_quality": {
            "events_published": len(filtered), "invalid_lines": invalid_lines,
            "operator_events_excluded": excluded_count, "non_public_events_excluded": non_public_count,
            "content_redactions": content_redactions, "geo_lookups": geo_lookups, "geo_failures": geo_failures,
            "enrichment_lookups": enrichment_lookups, "enrichment_failures": enrichment_failures,
            "privacy": "Operator and non-public source IPs excluded before aggregation; sensitive patterns redacted",
        },
        "provenance": {
            "source": "Cowrie JSON event log", "collection": "Live internet-exposed SSH/Telnet deception sensor",
            "interpretation": "Attacker-supplied observations; attribution and geolocation are indicative, not identity claims",
        },
    }


def navigator_layer(snapshot: dict[str, Any]) -> dict[str, Any]:
    maximum = max((item["count"] for item in snapshot["mitre"]), default=1)
    return {
        "name": "Greyfield observed techniques", "versions": {"attack": "19.2", "navigator": "5.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "ATT&CK techniques mapped conservatively from Greyfield Cowrie observations; counts represent observed evidence, not attributed incidents.",
        "techniques": [{"techniqueID": item["id"], "score": item["count"],
                        "comment": "; ".join(evidence["value"] for evidence in item["evidence"][:2]),
                        "enabled": True} for item in snapshot["mitre"]],
        "gradient": {"colors": ["#17131f", "#7857ff", "#ff5d73"], "minValue": 0, "maxValue": maximum},
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=Path(os.environ.get("COWRIE_JSON_LOG", DEFAULT_LOG)))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--layer-output", type=Path)
    parser.add_argument("--exclude-ip", action="append", default=[])
    parser.add_argument("--sensor-name", default="greyfield-primary")
    parser.add_argument("--sensor-status", choices=("operational", "degraded"), default="operational")
    parser.add_argument("--region", default="ap-mumbai-1")
    parser.add_argument("--public-endpoint")
    parser.add_argument("--geo-cache", type=Path)
    parser.add_argument("--geo-limit", type=int, default=40)
    parser.add_argument("--enrichment-cache", type=Path)
    parser.add_argument(
        "--enrichment-provider", action="append", choices=("malwarebazaar", "virustotal"), default=[],
    )
    parser.add_argument("--malwarebazaar-auth-key-file", type=Path)
    parser.add_argument("--virustotal-api-key-file", type=Path)
    parser.add_argument("--provider-limit", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.log.is_file():
        print(f"ERROR: Cowrie log does not exist: {args.log}", file=sys.stderr)
        return 1
    excluded_ips: set[str] = set()
    for item in args.exclude_ip:
        try:
            excluded_ips.add(str(ipaddress.ip_address(item)))
        except ValueError:
            print(f"ERROR: Invalid excluded IP: {item}", file=sys.stderr)
            return 1
    if args.public_endpoint and clean_public_endpoint(args.public_endpoint) is None:
        print(f"ERROR: Invalid public endpoint: {args.public_endpoint}", file=sys.stderr)
        return 1
    providers = list(dict.fromkeys(args.enrichment_provider))
    required_keys = {
        "malwarebazaar": args.malwarebazaar_auth_key_file,
        "virustotal": args.virustotal_api_key_file,
    }
    for provider in providers:
        if read_auth_key(required_keys[provider]) is None:
            print(f"ERROR: {provider} requires a readable, non-empty key file", file=sys.stderr)
            return 1
    if providers and args.enrichment_cache is None:
        print("ERROR: configured enrichment providers require --enrichment-cache", file=sys.stderr)
        return 1
    events, invalid = load_events(args.log)
    snapshot = build_snapshot(events, invalid, excluded_ips, args.sensor_name, args.region, args.sensor_status,
                              args.geo_cache, max(0, args.geo_limit), args.enrichment_cache,
                              providers, args.malwarebazaar_auth_key_file, args.virustotal_api_key_file,
                              max(0, args.provider_limit), args.public_endpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    if args.layer_output:
        args.layer_output.parent.mkdir(parents=True, exist_ok=True)
        args.layer_output.write_text(json.dumps(navigator_layer(snapshot), indent=2) + "\n", encoding="utf-8")
    print(f"Exported {snapshot['data_quality']['events_published']} public events to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
