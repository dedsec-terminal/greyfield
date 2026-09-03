# Architecture

## Trust boundaries

```text
Internet
  |
  |-- TCP 22 --> OCI stateful rule --> UFW/NAT --> Cowrie TCP 2222
  |-- TCP 23 --> OCI stateful rule --> UFW/NAT --> Cowrie TCP 2323
  |
Administrator public IP
  |
  `-- TCP 2223 --> OCI /32 rule --> UFW --> real OpenSSH
```

The OCI Security List is the outer firewall. UFW and the host NAT table are the
inner controls. Both layers must permit a flow for it to work.

## Host components

- `ubuntu`: OCI administrator account, authenticated only with an SSH key.
- `cowrie`: disabled-password service account that owns honeypot state.
- `/opt/greyfield`: immutable deployment scripts and configuration from Git.
- `/home/cowrie/honeypot`: virtual environment, runtime configuration, logs,
  downloads, TTY recordings, host keys, and PID files.
- `cowrie.service`: starts Cowrie as the unprivileged `cowrie` user.
- UFW: default-deny inbound host firewall.
- iptables NAT: redirects the privileged public ports to Cowrie's unprivileged
  listeners.
- Fail2ban: protects only the real administrator SSH service on port 2223.

## Security properties

- Cowrie never runs as root.
- Real SSH password and root logins are disabled.
- The cloud firewall and UFW both restrict real SSH to one administrator IPv4
  `/32`.
- Public attackers reach Cowrie, not the operating-system SSH service.
- Redirect activation is a separate final stage after administrator access and
  Cowrie health have both been independently verified.
- Captured downloads are untrusted and must never be executed.

## Data paths

| Data | Path |
|---|---|
| Runtime log | `/home/cowrie/honeypot/var/log/cowrie/cowrie.log` |
| Structured events | `/home/cowrie/honeypot/var/log/cowrie/cowrie.json` |
| TTY recordings | `/home/cowrie/honeypot/var/lib/cowrie/tty/` |
| Captured downloads | `/home/cowrie/honeypot/var/lib/cowrie/downloads/` |

Raw data stays off Git. Publish only the reviewed evidence contract.

## Public telemetry path

The optional dashboard is deliberately outside the honeypot's inbound trust
boundary:

```text
private Cowrie JSON
  -> operator-IP exclusion and sensitive-pattern redaction
  -> public attacker evidence and aggregate analysis
  -> telemetry Git branch
  -> GitHub Actions privacy validator
  -> static GitHub Pages dashboard
```

The evidence snapshot includes public attacker IPs and attacker-supplied text,
but never operator IPs, session artifacts, or captured payloads. The VM initiates the only dashboard-related network connection. It does not
listen on HTTP/HTTPS and requires no additional OCI ingress rule. A dedicated
repository deploy key is stored root-only and used solely by the hourly
publisher. Protect the default branch with a GitHub ruleset and do not grant
the deploy key a ruleset bypass; its intended write target is only the
`telemetry` branch (pushed with `--force-with-lease` as a single commit atop
`master` containing strictly the two public evidence files).

The public-data contract and deployment gates are documented in
[`DASHBOARD.md`](DASHBOARD.md).
