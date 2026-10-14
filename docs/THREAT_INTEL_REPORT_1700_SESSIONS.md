# Threat Intelligence Report: Deconstructing 1,700+ Automated SSH Brute-Force & Lateral Movement Sessions on Cloud Endpoints

**Author:** Swaraj Singh  
**Published:** October 2026  
**Sensor Infrastructure:** Greyfield Honeypot Observatory (Oracle Cloud Infrastructure, `137.23.33.116`, AP-Mumbai-1)  
**Correlated Threat Databases:** VirusTotal, Abuse.ch MalwareBazaar, MITRE ATT&CK Framework  
**Dataset Window:** 1,728 Active Inbound Adversary Sessions | 1,750 Authentication Attempts | 128 Hostile Threat IPs  

---

## Executive Summary

Between August and September 2026, an exposed cloud-native defensive sensor running an isolated Cowrie emulation stack on Oracle Cloud Infrastructure (OCI) logged **1,728 unsolicited remote attacker sessions** across SSH (`22/tcp`) and Telnet (`23/tcp`). 

Rather than relying on synthetic threat simulations or local sandbox mocks, this investigation dissects empirical adversary telemetries captured directly from the public internet. The data demonstrates how automated botnets (predominantly **Mirai** and **Gafgyt/Qbot** variants) conduct rapid initial credential spray attacks, verify pseudo-terminal responsiveness via hex-encoded string probes, disable defensive security controls, and execute stage-1 payload droppers.

```
       ADVERSARY ATTACK LIFECYCLE (OBSERVED IN GREYFIELD TELEMETRY)
  ┌────────────────────────────────────────────────────────────────────────┐
  │ 1. Initial Access: Credential Spray (T1110.001)                       │
  │    852 'root' / 97 'admin' attempts; Top pass: 'linuxshell', '123456'  │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ 2. Terminal Handshake & Probe Verification (T1059.004)                 │
  │    Hex probes: echo -e "\x47\x41\x59\x46\x47\x54" ("GAYFGT")          │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ 3. Defense Evasion & Environment Discovery (T1082 / T1083 / T1222.002) │
  │    Discovery of CPU architecture (cat /proc/cpuinfo) & chmod +x        │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │ 4. Ingress Tool Transfer (T1105) & Payload Staging                     │
  │    Ingress dropper: http://185.93.89.72/wget (SHA256: a6296a...6a4)    │
  │    Classified: trojan.shell/i7i1kt (VirusTotal / MalwareBazaar)        │
  └────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Initial Access: Credential Spray & Brute-Force Profiles

Out of **1,750 total authentication attempts**, 129 logins (7.3%) were intentionally accepted by the deception engine to observe post-exploitation adversary behaviors. 

Adversaries focused heavily on default administrative credentials and IoT/Linux device identities:

### Top Targeted Usernames
1. **`root`**: 852 attempts (48.7%) — Primary brute-force target across distributed botnets.
2. **`admin`**: 97 attempts (5.5%) — SOHO and cloud device targeting.
3. **`enable\x00`**: 84 attempts (4.8%) — Telnet command-mode escalation attempts.
4. **`user` / `ubuntu` / `support`**: 88 combined attempts — Cloud provider default identities (AWS/OCI/Azure templates).
5. **`deploy` / `postgres` / `jenkins` / `oracle`**: 44 attempts — Service-account credential hunting.

### Top Targeted Passwords
1. **`linuxshell\x00`**: 84 attempts — Embedded device and router exploit automation.
2. **`123456` / `123` / `1234`**: 157 combined attempts — Ubiquitous consumer device credential lists.
3. **`admin` / `password` / `root`**: 87 combined attempts — Standard dictionary defaults.
4. **`support` / `12345678`**: 47 attempts — Telecom/ISP default maintenance credentials.

---

## 2. Execution & Discovery: The Botnet Handshake

Once an interactive session was granted, **412 distinct command invocations** were captured and categorized.

Adversaries did not act manually; 94% of sessions executed an identical, automated **Botnet Discovery Handshake**:

```bash
# Observed Botnet Probe Sequence
sh
shell
system
echo -e "\x47\x41\x59\x46\x47\x54"
```

### Signature Analysis: The `GAYFGT` Echo Probe
The command `echo -e "\x47\x41\x59\x46\x47\x54"` was invoked across multiple independent sessions. 
- Decoding the hex string `\x47\x41\x59\x46\x47\x54` yields the ASCII string **`GAYFGT`**.
- This is the signature heartbeat probe of the **Qbot / Gafgyt / Mirai** malware families. 
- The botnet controller executes this echo probe immediately after authentication; if the remote shell fails to return the exact string back over stdout, the botnet aborts the session, concluding it is either a broken terminal or an uninstrumented sandbox.

---

## 3. MITRE ATT&CK Technique Mapping

Every malicious event recorded in Greyfield is mapped directly against the **MITRE ATT&CK Enterprise Matrix**:

| MITRE ATT&CK ID | Technique Name | Tactic | Observed Sessions | Observed Artifact / Telemetry Pattern |
| :--- | :--- | :--- | :---: | :--- |
| **T1059.004** | Unix Shell | Execution | **363** | Direct execution of `sh`, `bash`, and subshell commands |
| **T1110.001** | Password Guessing | Credential Access | **286** | Automated dictionary brute-force against port 22/23 |
| **T1083** | File & Directory Discovery | Discovery | **20** | Enumerating `/bin`, `/tmp`, `/proc/net/route`, and hidden dotfiles |
| **T1222.002** | Linux Permissions Modification | Defense Impairment | **19** | `chmod 777` and `chmod +x` invoked on dropped binaries |
| **T1070.004** | File Deletion | Defense Evasion | **10** | `rm -rf` cleanup scripts to eliminate dropper traces |
| **T1082** | System Information Discovery | Discovery | **7** | `cat /proc/cpuinfo` to detect MIPS/ARM/x86 architectures |
| **T1105** | Ingress Tool Transfer | Command & Control | **7** | Remote binary retrieval via `wget` and `curl` |
| **T1016** | System Network Configuration | Discovery | **2** | Inspecting local IP tables and routing tables |
| **T1057** | Process Discovery | Discovery | **2** | `ps -ef` inspection to kill rival crypto-miners |

---

## 4. Malware Dropper Ingress Analysis (T1105)

Greyfield captured **4 binary ingress attempts** where the adversary attempted to transfer a compiled remote payload to the honeypot:

### Analyzed Payload: `wget` Ingress Dropper
* **Source Dropper URL:** `http://185.93.89.72/wget`
* **SHA-256 Hash:** `a6296a79f44e21b76604d2d2bbf795d2cf380f70e39d45fbf166707ff3b4a6a4`
* **VirusTotal Classification:** `trojan.shell/i7i1kt` (10 Security Vendor Detections)
* **VirusTotal Threat Tags:** `detect-debug-environment`, `shell`, `sets-process-name`
* **Abuse.ch MalwareBazaar Record:** [Sample a6296a79...](https://bazaar.abuse.ch/sample/a6296a79f44e21b76604d2d2bbf795d2cf380f70e39d45fbf166707ff3b4a6a4/) (Tags: `cowrie`, `honeypot`, `sh`)

### Dropper Mechanism
The payload is a multi-stage shell script designed to query the CPU architecture (`uname -m`), download the corresponding architecture-specific ELF binary (MIPS, ARM, x86_64), grant execution permissions (`chmod 777`), launch the malicious process in the background, and immediately remove the initial dropper file (`rm -f`) to prevent forensic discovery.

---

## 5. Defensive Engineering & Architectural Countermeasures

1. **Strict Port & Network Isolation:** In the Greyfield architecture, port `22/tcp` (SSH) and `23/tcp` (Telnet) are redirected at the kernel level (`iptables` / OCI VCN security lists) directly to unprivileged containerized Cowrie listeners, while administrative management is pinned strictly to an isolated port (`2223/tcp`) accessible only via an administrative IPv4 `/32` whitelist.
2. **Fail-Closed Privacy Schema:** Raw session payloads, attacker TTY transcripts, and source network identifiers are sanitized and aggregated locally. Publication to the public observatory is strictly outbound-only via a dedicated telemetry branch, enforcing zero-leakage of operator secrets or unverified data.
3. **Behavioral Ingestion into SIEM / DFIR:** The raw JSON event streams generated by Greyfield are directly ingested into **TraceIR**, transforming unstructured honeypot sessions into canonical timeline events and Sigma-compatible detection rules.

## 6. Open Threat Intelligence Artifacts & Detections

To support open community defense, detection signatures and indicators derived from this investigation are published under open-source licenses:
- **Sigma Detection Rule:** [`../rules/sigma_mirai_gafgyt_probe.yml`](../rules/sigma_mirai_gafgyt_probe.yml) (Detects hex-encoded heartbeat echo handshakes in SIEM/EDR process telemetry).
- **Open IoC Feed (CSV):** [`iocs_mirai_gafgyt.csv`](iocs_mirai_gafgyt.csv) (Machine-readable indicators including dropper IPs, URLs, and SHA-256 hashes).
- **Public Honeypot Observatory:** [dedsec-terminal.github.io/greyfield](https://dedsec-terminal.github.io/greyfield/)

---

## Conclusion & Author Attribution

This telemetry investigation validates that automated cloud exploitation is dominated by rapid botnet commodity tooling seeking unpatched default credentials and executing predictable terminal handshakes. 

By analyzing empirical telemetry directly from production cloud endpoints, security engineers can tune detection rules (Sigma/YARA) to detect pre-attack reconnaissance and stage-1 payload ingress before lateral movement occurs.

* **Author:** Swaraj Singh ([@dedsec-terminal](https://github.com/dedsec-terminal))
* **Project Repository:** [github.com/dedsec-terminal/greyfield](https://github.com/dedsec-terminal/greyfield)
* **Live Public Observatory:** [dedsec-terminal.github.io/greyfield](https://dedsec-terminal.github.io/greyfield/)
