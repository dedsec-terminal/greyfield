# Greyfield

Greyfield is a defensive cloud honeypot and public threat observatory. It uses
[Cowrie](https://github.com/cowrie/cowrie) to record unsolicited SSH and Telnet
activity on an isolated Oracle Cloud Infrastructure instance, then publishes a
sanitized, evidence-backed view of what reached the decoy.

**[Open the live Internet Threat Observatory →](https://dedsec-terminal.github.io/greyfield/)**

**Public research sensor:** `137.23.33.116` — SSH on `22/tcp` and Telnet on
`23/tcp`. These are isolated Cowrie deception services; they do not provide
access to the underlying host.

The public dashboard covers source infrastructure, credential pressure,
attacker-supplied commands, payload retrieval attempts, and MITRE ATT&CK
techniques supported by retained evidence. It never publishes raw Cowrie logs,
session identifiers, TTY recordings, captured files, operator addresses,
administrator access details, or cloud secrets.

## What this project demonstrates

- Cloud honeypot deployment with strict separation between bait services and
  administrator access.
- Defensive telemetry engineering from private collection to a reviewed public
  evidence contract.
- Approximate network and geolocation enrichment without treating infrastructure
  as a person's identity.
- Evidence-constrained ATT&CK mapping and hash-only provider correlation.
- Automated privacy validation and outbound-only publication through GitHub
  Actions and GitHub Pages.

## Architecture

```text
Internet                         Administrator IP only
  │                                        │
  ├─ TCP 22 ─┐                              └─ TCP 2223 ── real OpenSSH
  └─ TCP 23 ─┤
             ▼
       OCI firewall + UFW/NAT
             │
             ├─ 2222 ── Cowrie SSH
             └─ 2323 ── Cowrie Telnet

Private Cowrie JSON
  └─ filter + redact + aggregate + enrich
       └─ orphan telemetry branch (metrics.json + attack-layer.json only)
            └─ fail-closed validation ── GitHub Pages observatory
```

Collection stays private on the VM. Publication is outbound-only, and every
field must pass the repository's schema and privacy checks before deployment.
The `telemetry` branch is deliberately orphaned from `master`; GitHub may show
it as ahead or behind because it is a rolling two-file data channel, not a code
branch intended for merging or pull requests.

The sensor is intentionally discoverable through this repository and the live
observatory. Internet-wide indexes such as Shodan already crawl public services;
indexing confirms exposure but does not guarantee additional attacks or broader
ATT&CK coverage. Greyfield measures observed evidence rather than manufacturing
traffic or inflating event counts.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust boundaries and
[`docs/DASHBOARD.md`](docs/DASHBOARD.md) for the public-data contract.

## Supported baseline

| Component | Supported configuration |
|---|---|
| Cloud host | OCI `VM.Standard.E2.1.Micro`, x86-64, 1 GB RAM |
| Operating system | `Canonical-Ubuntu-22.04-2026.08.25-0` |
| Honeypot | Cowrie `3.0.13` |
| Administration | Windows 10/11 with OpenSSH |

Ubuntu 24.04 is intentionally outside the supported baseline because its `ufw`
package conflicts with the `iptables-persistent` dependency used by the current
redirect-persistence procedure.

## Network model

| Public port | Host destination | Access |
|---|---|---|
| `22/tcp` | Cowrie SSH on `2222` | Internet |
| `23/tcp` | Cowrie Telnet on `2323` | Internet |
| `2223/tcp` | Real OpenSSH server | Administrator IPv4 `/32` only |

Real SSH must be verified from a second, independent terminal on port `2223`
before public port `22` is handed to Cowrie. That gate is mandatory.

## Staged deployment

1. Provision the OCI network and Ubuntu instance with the
   [OCI deployment guide](docs/OCI_DEPLOYMENT.md).
2. Clone Greyfield to `/opt/greyfield` while real SSH still uses port `22`.
3. Follow the numbered stages in [`docs/RUNBOOK.md`](docs/RUNBOOK.md).
4. Confirm every administrator-access, listener, firewall, persistence, and
   logging gate before advancing.
5. Configure telemetry publication separately with
   [`docs/DASHBOARD.md`](docs/DASHBOARD.md).

The stages are intentionally not combined. Final activation occurs only after
administrator SSH and both Cowrie listeners have been proven healthy.

## Evidence boundary

Greyfield may publish globally routable source IPs, approximate country/city/ASN
context, attempted credentials, inert command text, artifact URLs with query
material removed, SHA-256 hashes, and qualified provider observations.

Before aggregation, the exporter removes configured operator addresses and all
non-public sources. It redacts email-, token-, private-key-, and URL-query-like
patterns. The validator independently rejects forbidden fields, unexpected
files, stale snapshots, cross-record inconsistencies, and data outside the
publication ceilings.

Interpretation remains deliberately constrained:

- An IP address identifies observed infrastructure, not a person.
- Geolocation and network ownership are approximate enrichment.
- ATT&CK mappings describe evidenced behavior, not attribution or impact.
- A payload request is transfer evidence, not proof of execution.
- Provider labels are time-stamped third-party observations, not Greyfield
  malware-family attribution.

## Repository map

```text
configs/          Cowrie runtime configuration
dashboard/        Static public observatory and evidence explorer
docs/             Architecture, deployment, dashboard, and operations guides
scripts/          Staged installation, export, validation, and verification
systemd/          Cowrie and telemetry publication units
tests/            Synthetic exporter, privacy, and schema tests
THIRD_PARTY_NOTICES.md  Licenses for bundled public map data
```

## Validation

Run the same core checks enforced by CI before changing deployment behavior or
the public evidence contract:

```bash
bash -n scripts/*.sh
shellcheck scripts/*.sh
python3 -m unittest discover -s tests -v
node --check dashboard/assets/app.js
node --check dashboard/assets/evidence.js
git diff --check
```

The dashboard workflow additionally validates the latest telemetry snapshot and
ATT&CK Navigator layer before GitHub Pages receives an artifact.

## Safety

Use Greyfield only on a dedicated disposable host. Do not place personal data,
production services, reusable credentials, unrelated SSH keys, raw logs,
captured malware, or cloud secrets in this repository. Cowrie may make outbound
requests while emulating attempted downloads; never execute a captured sample.

## License

Released under the [MIT License](LICENSE). Copyright © 2026 Swaraj Singh.
