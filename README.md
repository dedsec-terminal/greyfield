# Greyfield

Greyfield is a defensive cloud honeypot and public threat-observation system.
It captures unsolicited SSH and Telnet activity with
[Cowrie](https://github.com/cowrie/cowrie), preserves the original evidence on
an isolated Oracle Cloud Infrastructure instance, and publishes a deliberately
restricted intelligence view for external analysis.

The project is built around a separation that matters operationally: collection
is private, publication is outbound-only, and every public field passes an
explicit evidence and privacy contract. The observable result is not a stream
of raw logs. It is a controlled account of where activity originated, which
credentials and commands were supplied, what payload retrievals were attempted,
and which ATT&CK behaviors the retained evidence can support.

This design demonstrates cloud security engineering, SOC telemetry handling,
threat-intelligence enrichment, detection mapping, and governance of sensitive
security evidence without presenting enrichment as identity or attribution.

The companion observatory is a static GitHub Pages site driven by a validated
two-file telemetry branch. Raw Cowrie logs, captured files, TTY recordings,
session identifiers, operator addresses, secrets, and administrator access
details never enter the public branch. See the
[dashboard deployment guide](docs/DASHBOARD.md).

## Supported baseline

- OCI `VM.Standard.E2.1.Micro` (x86-64, 1 GB RAM)
- `Canonical-Ubuntu-22.04-2026.08.25-0`
- Cowrie `3.0.13`
- Windows 10/11 with OpenSSH for administration

Ubuntu 24.04 is intentionally not supported by the initial scripts. Its current
`ufw` package conflicts with `iptables-persistent`, which Greyfield uses to
persist the public-port redirects.

## Port model

| Public port | Host destination | Access |
|---|---|---|
| `22/tcp` | Cowrie SSH on `2222` | Internet |
| `23/tcp` | Cowrie Telnet on `2323` | Internet |
| `2223/tcp` | Real OpenSSH server | Administrator IP only |

## Deployment order

1. Provision the OCI network and instance using [the OCI guide](docs/OCI_DEPLOYMENT.md).
2. Connect to the new instance on port 22 and clone this repository to
   `/opt/greyfield`.
3. Run the staged host procedures in [the runbook](docs/RUNBOOK.md).
4. Verify administrator access, Cowrie listeners, firewall rules, persistence,
   and logging before leaving the instance unattended.

Never skip a verification gate. In particular, do not hand public port 22 to
Cowrie until a second, independent administrator login on port 2223 succeeds.

## Repository layout

```text
configs/          Cowrie configuration
dashboard/        Static public threat observatory
docs/             Architecture, OCI deployment, and operating runbook
scripts/          Staged host installation and verification
systemd/          Cowrie and telemetry publication units
tests/            Synthetic privacy and aggregation tests
```

## Dashboard evidence model

The dashboard publishes globally routable source addresses, approximate network
and location context, attempted credentials, inert command text, stripped
artifact URLs, SHA-256 hashes, and evidence-backed ATT&CK mappings. Optional
malware-family correlation sends only an unseen hash to the configured provider
and records the result as known, unknown, or unavailable with its source and
lookup time.

Configured operator addresses and all non-public sources are removed before
aggregation. Email, token, private-key, and URL-query patterns are redacted.
ATT&CK mappings describe observed behavior; they do not prove attribution,
execution, compromise, or impact. Session identifiers, TTY recordings, captured
files, and raw logs never enter GitHub.

## Safety boundary

This host must contain no personal data, production services, reusable cloud
credentials, or unrelated SSH keys. Cowrie emulates attacker commands, but it
can make real outbound requests to capture attempted malware downloads. Never
execute captured samples.

## Inspiration

Greyfield's deployment model was informed by
[ajcyberdefense/cowrie-honeypot](https://github.com/ajcyberdefense/cowrie-honeypot)
and the official Cowrie, Ubuntu, and OCI documentation. Greyfield is maintained
as a separate project rather than a fork.

## License

MIT. See [LICENSE](LICENSE).
