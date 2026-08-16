# Greyfield Threat Model

**Version:** 1.0  
**Date:** 2026-08  
**Scope:** Phase 1 (Infrastructure & Host Hardening) through Phase 7 (Publishing Pipeline)  
**Classification:** Portfolio documentation — public

---

## 1. Purpose of This Document

This document defines the threat model for the Greyfield honeypot deployment.
It records the risks we have identified, the mitigations we have applied, and
the residual risks that the operator accepts. It serves two purposes:

1. **Operational:** Ensure no obvious attack surface is left unconsidered
   before the VM is exposed to live attacker traffic on ports 22 and 23
2. **Portfolio:** Demonstrate structured threat reasoning — a core skill for
   SOC analyst and threat intelligence roles

---

## 2. System Overview

```
Internet
   │
   ▼
OCI Security List (network ACL)
   │  allows: 22/tcp, 23/tcp (open), 4822/tcp (admin-IP only)
   ▼
Ubuntu 24.04 VM — VM.Standard.E2.1.Micro (1 OCPU, 1GB RAM)
   │
   ├── UFW (host firewall, default-deny inbound)
   │
   ├── iptables PREROUTING
   │     22/tcp  → 127.0.0.1:2222
   │     23/tcp  → 127.0.0.1:2223
   │
   ├── Cowrie 3.x (runs as 'cowrie' — unprivileged user, no login shell)
   │     Listens: 2222/tcp (SSH), 2223/tcp (Telnet)
   │     Logs:    /opt/cowrie/var/log/cowrie/cowrie.json
   │
   ├── Flask dashboard (port 80, local or home-IP-only)
   │
   └── Admin SSH: port 4822, key-auth only, Fail2ban rate-limited
```

---

## 3. Assets

| Asset | Sensitivity | Notes |
|-------|-------------|-------|
| VM root access | Critical | Loss means full host compromise |
| Admin SSH private key | Critical | Stored only on operator's local machine |
| Real admin port (4822) | High | Should not appear in public documentation |
| API keys (.env) | High | AbuseIPDB, ipinfo.io — gitignored, never committed |
| Cowrie log data | Medium | Attacker behavior — valuable, not personally sensitive |
| GitHub Pages report | Low | Intentionally public |

---

## 4. Threat Actors

This deployment is an intentional lure. We model the realistic population of
actors likely to interact with a honeypot on ports 22/23:

| Actor Type | Sophistication | Goal |
|------------|---------------|------|
| Automated bots / botnets | Low | Credential stuffing, malware propagation |
| Script kiddies | Low–Medium | Opportunistic shell access, bragging |
| Cryptocurrency miners | Low–Medium | Install cryptominer, abuse compute |
| Ransomware affiliates | Medium | Lateral movement pivot point |
| APT reconnaissance | High (rare) | Would likely detect honeypot and disengage |

**Primary threat for this deployment:** Automated bots and low-sophistication
opportunists. An APT with detection capabilities would fingerprint Cowrie's
SSH banner or behavioral anomalies and leave — which is fine; we are here to
capture the bulk traffic, not APTs.

---

## 5. Threat Scenarios & Mitigations

### 5.1 Sandbox Escape — Attacker Breaks Out of Cowrie

**Scenario:** An attacker interacting with Cowrie identifies it as a honeypot
simulator (or simply attempts a privilege escalation) and exploits a
vulnerability in Cowrie itself, the Python runtime, or the underlying OS to
escape the simulated environment and gain a real shell on the host.

**Likelihood:** Low. Cowrie is a mature, widely deployed honeypot with active
security maintenance. The simulated filesystem presents no real binaries to
exploit.

**Impact if realized:** High. An attacker with a real shell on the host could:
- Exfiltrate API keys from the `.env` file
- Pivot to other OCI resources in the tenancy
- Use the VM for malicious outbound activity (DDoS, spam)
- Destroy log evidence

**Mitigations applied:**

| Mitigation | Where configured |
|-----------|-----------------|
| Cowrie runs as `cowrie` user — no login shell, no sudo access | `setup_host.sh` Step 2 |
| Cowrie process does not run as root | Verified in Phase 2 systemd unit |
| `.env` file owned `root:root`, mode `600` | Phase 2 setup |
| No SSH authorized_keys for `cowrie` user | Verified at setup |
| UFW default-deny: cowrie cannot initiate inbound connections | `setup_host.sh` Step 5 |
| OS packages kept current | `setup_host.sh` Step 1 + weekly cron |

**Residual risk:** A zero-day in Cowrie or Python could enable escape.
Accepted — this is a portfolio honeypot, not a production system. We monitor
for unusual outbound connections as a compensating control.

---

### 5.2 Host Data Exposure — Attacker Reads Real Files

**Scenario:** Through misconfiguration, an attacker is able to read real host
files (e.g., `/etc/passwd`, `/home/ubuntu/.ssh/`, `.env`) through Cowrie's
filesystem emulation or an escape path.

**Likelihood:** Very low with correct configuration.

**Impact if realized:** High (API key leakage, real user account information).

**Mitigations applied:**

| Mitigation | Detail |
|-----------|--------|
| Cowrie's filesystem is a synthetic overlay (not a bind-mount of `/`) | By design in Cowrie — real filesystem not accessible from within simulation |
| `.env` never committed to git | `.gitignore` enforced in Phase 1 repo scaffold |
| API keys in `.env` scoped to read-only roles where possible | AbuseIPDB: report-only key, ip-api: no auth required |
| No database credentials in `.env` — SQLite file on disk only | No password attack surface |

---

### 5.3 Admin SSH Brute Force — Real Shell Compromised

**Scenario:** An attacker enumerates or guesses port 4822 and brute-forces the
admin SSH credentials.

**Likelihood:** Low (non-standard port + key-auth only + Fail2ban).

**Impact if realized:** Critical (full root access via sudo).

**Mitigations applied:**

| Mitigation | Where configured |
|-----------|-----------------|
| SSH moved to port 4822 (non-default) | `setup_host.sh` Step 3 |
| `PasswordAuthentication no` in `sshd_config` | `setup_host.sh` Step 3 |
| `PermitRootLogin no` | `setup_host.sh` Step 3 |
| `MaxAuthTries 3` | `setup_host.sh` Step 3 |
| Fail2ban: 3 failures → 1-hour ban | `setup_host.sh` Step 6 |
| OCI Security List: port 4822 source-restricted to admin IP | `oci_security_list.md` Step 3 |

**Residual risk:** If the admin's private key is stolen, all above mitigations
fail. Key management is the operator's responsibility (e.g., passphrase-protected
key, stored in local keychain only).

---

### 5.4 Resource Exhaustion — VM Overwhelmed by Attacker Traffic

**Scenario:** High-volume automated attacks (connection floods, large file
uploads within Cowrie, recursive command loops) exhaust the 1GB RAM or disk
on the micro VM, causing service disruption.

**Likelihood:** Medium. Automated botnets generate significant connection rates.

**Impact if realized:** Medium (honeypot goes offline, data collection stops;
no data loss unless disk fills and logs are truncated).

**Mitigations applied:**

| Mitigation | Detail |
|-----------|--------|
| Cowrie connection rate limiting | `max_connections` and `interactive_timeout` configured in Phase 2 |
| UFW connection limiting on 22/23 | Can be added if flood detected (not enabled by default — would bias data) |
| Log rotation with max size cap | Configured in Phase 2 |
| Disk monitoring alert (systemd timer) | Phase 7 monitoring hook |

---

### 5.5 Outbound Abuse — VM Used as Attack Pivot

**Scenario:** Via an escape or a misconfigured service, attacker uses the VM to
send spam, participate in DDoS, or scan other hosts.

**Likelihood:** Low with correct configuration.

**Mitigations applied:**

- UFW `default allow outgoing` is permissive — intentional, as Cowrie needs
  outbound for malware download capture simulation and the pipeline needs HTTPS
  for API calls and GitHub Pages push
- OCI's Abuse team monitors egress and will suspend the account for egress abuse
  — accepted residual risk for a free-tier VM

**Compensating control:** Monitor outbound bytes via `nethogs` or `vnstat`
periodically during the first week.

---

## 6. Why Cowrie Runs Unprivileged

Ports below 1024 require root or `CAP_NET_BIND_SERVICE`. Rather than grant
either to Cowrie, we use iptables `PREROUTING REDIRECT` rules to forward
incoming connections on port 22 → 2222 and port 23 → 2223 at the kernel
level before the process ever sees the packet. Cowrie listens on 2222/2223,
which any unprivileged process may bind.

This approach means:
- The Cowrie Python process runs as `cowrie` (UID: system, no shell, no sudo)
- A vulnerability in Cowrie cannot directly escalate to root via socket binding
- The real SSH daemon still controls port 4822 as root (its normal operation)

---

## 7. Why Admin SSH Was Moved Off Port 22

Port 22 is now exclusively used as the honeypot lure surface, redirected to
Cowrie on port 2222. Leaving real sshd on port 22 would mean:
1. Real admin traffic interleaved with honeypot traffic — ambiguous logs
2. Real credentials or key-auth handshakes visible to any tap on the network
3. Real sshd exposed to the same brute-force bots we are trying to capture

Moving admin SSH to port 4822 separates real management from honeypot surfaces
entirely. Port 4822 is further restricted to the admin's home IP at the OCI
Security List layer — it is not even routable to from the general internet.

---

## 8. Out-of-Scope Threats

The following are explicitly out of scope for this deployment and accepted:

| Threat | Reason out of scope |
|--------|---------------------|
| OCI hypervisor compromise | Infrastructure vendor responsibility |
| Supply-chain attack on Cowrie package | We pin to a specific release hash in Phase 2 |
| Data integrity of captured logs | No tamper-evidence requirement for portfolio use |
| GDPR / privacy compliance | IP addresses captured are attacker IPs from scanning/botnet activity |

---

## 9. Review Cadence

This threat model should be reviewed:
- Before each new phase is deployed
- When the deployed software stack changes materially
- If an anomalous event is observed in logs

*Last reviewed: 2026-08 (Phase 1)*
