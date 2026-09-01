# Greyfield public threat observatory

Greyfield publishes an outbound-only static dashboard through GitHub Pages. The
VM does not run a web server, and the dashboard needs no OCI port `80` or `443`
rule.

```text
Cowrie JSON (private on VM)
  -> remove configured operator IPs and non-public addresses
  -> redact email, token, private-key, and URL-query patterns
  -> enrich top public sources through a private local cache
  -> optionally correlate unseen SHA-256 hashes through a hash-only API lookup
  -> telemetry branch: metrics.json + attack-layer.json only
  -> GitHub Actions cross-file schema and privacy validation
  -> GitHub Pages
```

## What becomes public

The evidence contract intentionally includes globally routable attacker IPs,
approximate country/city/ASN context, attempted usernames and passwords,
commands rendered as inert text, artifact URLs without query strings, SHA-256
hashes, event times, the public bait endpoint, qualified malware-family context,
and evidence-backed ATT&CK mappings.

It never includes configured operator IPs, private/reserved addresses, Cowrie
session IDs, TTY recordings, captured binaries, administrator or private
destination infrastructure, private keys, raw logs, email-like strings,
token-like strings, or URL queries.
The local Cowrie evidence is not deleted or rewritten; exclusion applies to the
public export so forensic integrity is preserved.

IP geolocation is approximate and must not be treated as a person's location or
identity. Free enrichment uses [IPWHOIS.IO](https://ipwhois.io/documentation),
is cached at `/var/lib/greyfield-dashboard/geo-cache.json`, and is capped at 40
new lookups per publication.

ATT&CK entries describe behavior supported by the exported event. They are
analyst-oriented mappings, not proof of attribution, compromise, successful
execution, or impact. A retrieved artifact is mapped to `T1105` only as
observed transfer evidence.

## 1. Enable GitHub Pages

After the dashboard code is committed to `master`:

1. Open the repository's **Settings > Pages**.
2. Set **Build and deployment > Source** to **GitHub Actions**.
3. Open **Actions > dashboard-pages** and run it once.

The Pages workflow fails closed when the `telemetry` branch is absent, stale,
malformed, or contains files outside the two-file public evidence contract. No
demonstration snapshot is used as a production fallback.

## 2. Create the telemetry deploy key

Connect to real administrator SSH on port `2223` and create a dedicated key:

```bash
sudo install -d -o root -g root -m 0700 /etc/greyfield-dashboard
sudo ssh-keygen -q -t ed25519 -N '' \
  -C 'greyfield telemetry publisher' \
  -f /etc/greyfield-dashboard/deploy_key
sudo cat /etc/greyfield-dashboard/deploy_key.pub
```

Copy only the public key. Add it under **Repository Settings > Deploy keys**,
name it `Greyfield telemetry publisher`, and enable **Allow write access**. Do
not reuse the OCI administrator key. Protect `master` with a GitHub ruleset and
do not grant this deploy key a bypass; its intended target is only `telemetry`.

## 3. Pin GitHub's SSH host key

```bash
printf '%s\n' \
  'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' \
  | sudo tee /etc/greyfield-dashboard/known_hosts >/dev/null
sudo chown root:root /etc/greyfield-dashboard/known_hosts
sudo chmod 0600 /etc/greyfield-dashboard/known_hosts
ssh-keygen -lf /etc/greyfield-dashboard/known_hosts
```

The fingerprint must match GitHub's published Ed25519 fingerprint:
`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`. Stop if it differs.

## 4. Configure the public-evidence boundary

Create the root-only configuration:

```bash
sudo install -o root -g root -m 0600 /dev/null /etc/greyfield-dashboard/config
sudoedit /etc/greyfield-dashboard/config
```

Use this configuration. Replace the placeholders with every personal network
address used to test or administer the honeypot, including old addresses still
present in Cowrie's retained log:

```bash
REPO_SSH=git@github.com:dedsec-terminal/greyfield.git
DEPLOY_KEY=/etc/greyfield-dashboard/deploy_key
KNOWN_HOSTS=/etc/greyfield-dashboard/known_hosts
LOG_FILE=/home/cowrie/honeypot/var/log/cowrie/cowrie.json
EXPORTER=/opt/greyfield/scripts/export-dashboard.py
VALIDATOR=/opt/greyfield/scripts/validate-dashboard.py
SENSOR_NAME=greyfield-honeypot
SENSOR_STATUS=operational
REGION=ap-mumbai-1
PUBLIC_ENDPOINT=YOUR_PUBLIC_IP_OR_HOSTNAME
EXCLUDE_IPS="CURRENT_ADMIN_IP PREVIOUS_TEST_IP ANOTHER_PERSONAL_IP"
GEO_CACHE=/var/lib/greyfield-dashboard/geo-cache.json
GEO_LIMIT=40
FAMILY_PROVIDER=none
FAMILY_CACHE=/var/lib/greyfield-dashboard/family-cache.json
FAMILY_LIMIT=20
```

The exporter removes matching events before calculating any counter, source
table, timeline, credential list, command list, or ATT&CK technique. The
publisher then runs the validator with the same deny list as a second gate.

If your public IP changes, add the new and old values here. Separately update
the OCI and UFW `/32` rules for real SSH on port `2223`.

`PUBLIC_ENDPOINT` is intentionally limited to an IP address or hostname. The
published service list is fixed to Cowrie SSH on public port `22` and Cowrie
Telnet on public port `23`; the validator rejects administrator port `2223`.

### Optional hash-only family correlation

Family correlation is disabled by default. To enable MalwareBazaar, create a
separate root-only file containing your MalwareBazaar Auth-Key, then add:

```bash
FAMILY_PROVIDER=malwarebazaar
FAMILY_AUTH_KEY_FILE=/etc/greyfield-dashboard/malwarebazaar-auth-key
```

The exporter submits only previously unseen, syntactically valid SHA-256
values. It never reads, uploads, downloads, or executes an artifact. Results
are cached locally and published as `known`, `unknown`, or `unavailable` with
the provider and lookup time. A returned family name is third-party context,
not an independently verified attribution. VirusTotal is not integrated and
must not be enabled without a separate explicit decision and API key.

## 5. Install and test publication

```bash
sudo install -o root -g root -m 0755 \
  /opt/greyfield/scripts/publish-dashboard-data.sh \
  /usr/local/sbin/greyfield-publish-dashboard
sudo install -o root -g root -m 0644 \
  /opt/greyfield/systemd/greyfield-telemetry.service \
  /etc/systemd/system/greyfield-telemetry.service
sudo install -o root -g root -m 0644 \
  /opt/greyfield/systemd/greyfield-telemetry.timer \
  /etc/systemd/system/greyfield-telemetry.timer
sudo systemctl daemon-reload
sudo systemctl start greyfield-telemetry.service
sudo systemctl status greyfield-telemetry.service --no-pager
```

Run the service manually once. The first successful run creates the orphan
`telemetry` branch. Inspect that publication on GitHub before enabling
automation. It must contain only:

- `metrics.json`
- `attack-layer.json`

Search both files for every excluded operator IP. Confirm that no raw session
identifier, URL query, private address, administrator endpoint, token-like
value, or unexpected file is present. Do not enable the timer if any check
fails.

```bash
sudo systemctl enable --now greyfield-telemetry.timer
systemctl list-timers greyfield-telemetry.timer --no-pager
```

The VM refreshes telemetry hourly with a randomized delay. This schedule keeps
the public observatory current; it is not an OCI instance keepalive mechanism.
GitHub Actions checks for a new snapshot every 15 minutes and rejects evidence
older than three hours or outside the schema and privacy contract.

## Operations

```bash
sudo systemctl status greyfield-telemetry.service --no-pager
sudo journalctl -u greyfield-telemetry.service -n 30 --no-pager
```

Re-run the service after changing the exclusion list, exporter, or validator.
Revoke and rotate the deploy key when the VM is rebuilt or suspected
compromised. Never paste raw Cowrie logs into GitHub, an issue, or a chat.

### Exceptional operator-evidence removal

Normally, preserve the raw Cowrie evidence and rely on export exclusion. If an
authorized controlled test accidentally records an operator address or session,
first run the removal utility without `--apply`:

```bash
sudo python3 /opt/greyfield/scripts/purge-operator-evidence.py \
  --operator-ip CURRENT_OR_TEST_OPERATOR_IP
```

Review only the reported counts. To apply the scoped removal, stop Cowrie,
repeat the command with `--apply`, verify a subsequent dry run reports zero,
and restart the service:

```bash
sudo systemctl stop cowrie.service
sudo python3 /opt/greyfield/scripts/purge-operator-evidence.py \
  --operator-ip CURRENT_OR_TEST_OPERATOR_IP \
  --apply
sudo python3 /opt/greyfield/scripts/purge-operator-evidence.py \
  --operator-ip CURRENT_OR_TEST_OPERATOR_IP
sudo systemctl start cowrie.service
sudo systemctl is-active cowrie.service
```

This operation rewrites matching Cowrie JSON/text records and deletes associated
TTY or download files for the matched sessions without creating a backup. It is
irreversible and must never be used to erase unrelated attacker evidence.
