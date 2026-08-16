# Greyfield — Phase 1 Hardening Checklist

**Scope:** Infrastructure & Host Hardening  
**Target:** Oracle Cloud Ubuntu 24.04 LTS — VM.Standard.E2.1.Micro  
**Run after:** `setup_host.sh` completes without errors

Mark each item ✅ after verification before proceeding to Phase 2 (Cowrie deployment).

---

## 1. System Updates

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 1.1 | No pending security updates | `sudo apt list --upgradable 2>/dev/null \| grep -i security` | Empty output (or only non-critical packages) |
| 1.2 | UFW package installed | `dpkg -l ufw \| grep '^ii'` | Line showing `ufw` with status `ii` |
| 1.3 | Fail2ban package installed | `dpkg -l fail2ban \| grep '^ii'` | Line showing `fail2ban` with status `ii` |
| 1.4 | netfilter-persistent installed | `dpkg -l netfilter-persistent \| grep '^ii'` | Line showing package with status `ii` |

---

## 2. Cowrie System User

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 2.1 | User `cowrie` exists | `id cowrie` | Output shows UID, GID, groups |
| 2.2 | `cowrie` has no login shell | `getent passwd cowrie \| cut -d: -f7` | `/sbin/nologin` or `/usr/sbin/nologin` |
| 2.3 | `cowrie` cannot sudo | `sudo -l -U cowrie` | `User cowrie is not allowed to run sudo` |
| 2.4 | `cowrie` has no password | `sudo passwd -S cowrie \| awk '{print $2}'` | `L` (locked) or `NP` (no password) |
| 2.5 | `cowrie` has no home directory (or empty one) | `getent passwd cowrie \| cut -d: -f6` | `/home/cowrie` should not exist, or is empty |

---

## 3. SSH Admin Port (4822)

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 3.1 | sshd listening on 4822 | `sudo ss -tlnp \| grep sshd` | Entry with `*:4822` or `0.0.0.0:4822` |
| 3.2 | sshd NOT listening on 22 | `sudo ss -tlnp \| grep ':22 '` | No output (port 22 is cowrie's territory) |
| 3.3 | `Port` directive in sshd_config | `grep '^Port' /etc/ssh/sshd_config` | `Port 4822` |
| 3.4 | PasswordAuthentication disabled | `grep '^PasswordAuthentication' /etc/ssh/sshd_config` | `PasswordAuthentication no` |
| 3.5 | Root login disabled | `grep '^PermitRootLogin' /etc/ssh/sshd_config` | `PermitRootLogin no` |
| 3.6 | MaxAuthTries set | `grep '^MaxAuthTries' /etc/ssh/sshd_config` | `MaxAuthTries 3` |
| 3.7 | sshd_config is valid | `sudo sshd -t && echo OK` | `OK` (no output from sshd -t means no errors) |
| 3.8 | Can actually connect on 4822 | `ssh -p 4822 ubuntu@<vm-ip> echo ok` (from local machine) | `ok` |

---

## 4. OCI Default iptables Rules Flushed

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 4.1 | No REJECT rules in INPUT chain | `sudo iptables -L INPUT -n \| grep REJECT` | No output |
| 4.2 | No REJECT rules in FORWARD chain | `sudo iptables -L FORWARD -n \| grep REJECT` | No output |
| 4.3 | Default INPUT policy | `sudo iptables -L INPUT \| head -1` | `Chain INPUT (policy ACCEPT)` |
| 4.4 | Default FORWARD policy | `sudo iptables -L FORWARD \| head -1` | `Chain FORWARD (policy ACCEPT)` |
| 4.5 | No stale PREROUTING rules from OCI | `sudo iptables -t nat -L PREROUTING -n` | Only the two Greyfield REDIRECT rules (22→2222, 23→2223) |

---

## 5. UFW Rules

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 5.1 | UFW is active | `sudo ufw status` | `Status: active` |
| 5.2 | Default deny inbound | `sudo ufw status verbose \| grep 'Default'` | `Default: deny (incoming)` |
| 5.3 | Port 4822 allowed | `sudo ufw status \| grep 4822` | `4822/tcp  ALLOW IN  Anywhere` |
| 5.4 | Port 22 allowed | `sudo ufw status \| grep ' 22'` | `22/tcp  ALLOW IN  Anywhere` |
| 5.5 | Port 23 allowed | `sudo ufw status \| grep ' 23'` | `23/tcp  ALLOW IN  Anywhere` |
| 5.6 | Port 80 allowed | `sudo ufw status \| grep ' 80'` | `80/tcp  ALLOW IN  Anywhere` |
| 5.7 | Rate limit on 4822 | `sudo ufw status \| grep 4822` | Shows `LIMIT` not just `ALLOW` |

---

## 6. Fail2ban

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 6.1 | Fail2ban service is running | `sudo systemctl is-active fail2ban` | `active` |
| 6.2 | Fail2ban enabled on boot | `sudo systemctl is-enabled fail2ban` | `enabled` |
| 6.3 | Greyfield jail loaded | `sudo fail2ban-client status` | `greyfield-admin-ssh` listed in `Jail list` |
| 6.4 | Jail configuration | `sudo fail2ban-client status greyfield-admin-ssh` | Shows `Currently failed: 0`, `Currently banned: 0` |
| 6.5 | Jail targets correct port | `sudo fail2ban-client get greyfield-admin-ssh port` | `4822` |
| 6.6 | maxretry is 3 | `sudo fail2ban-client get greyfield-admin-ssh maxretry` | `3` |
| 6.7 | bantime is 3600s | `sudo fail2ban-client get greyfield-admin-ssh bantime` | `3600` |

---

## 7. iptables PREROUTING Redirects

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 7.1 | Redirect 22→2222 exists | `sudo iptables -t nat -L PREROUTING -n \| grep 'dpt:22'` | Line with `redir ports 2222` |
| 7.2 | Redirect 23→2223 exists | `sudo iptables -t nat -L PREROUTING -n \| grep 'dpt:23'` | Line with `redir ports 2223` |
| 7.3 | No duplicate redirect rules | `sudo iptables -t nat -L PREROUTING -n \| grep -c 'REDIRECT'` | `2` (exactly two REDIRECT rules) |
| 7.4 | Full PREROUTING chain | `sudo iptables -t nat -L PREROUTING -n -v --line-numbers` | Displays both rules cleanly, no unexpected entries |

---

## 8. Rule Persistence

| # | Check | Verification Command | Expected Result |
|---|-------|---------------------|-----------------|
| 8.1 | Persisted IPv4 rules file exists | `cat /etc/iptables/rules.v4` | Contains PREROUTING REDIRECT entries |
| 8.2 | Persisted IPv6 rules file exists | `cat /etc/iptables/rules.v6` | File present (may be minimal if no IPv6 rules) |
| 8.3 | netfilter-persistent enabled | `sudo systemctl is-enabled netfilter-persistent` | `enabled` |
| 8.4 | **Reboot persistence test** | `sudo reboot` → reconnect on 4822 → re-run checks 7.1 and 7.2 | Redirect rules survive reboot |

> ⚠ **Do not skip check 8.4.** Rules that disappear on reboot are a common
> failure mode. Always verify persistence with an actual reboot before Phase 2.

---

## 9. OCI Security List (Manual Verification)

These checks are performed from your local machine, not the VM.

| # | Check | Verification Command (local) | Expected Result |
|---|-------|------------------------------|-----------------|
| 9.1 | Port 4822 reachable from admin IP | `nc -zv <vm-ip> 4822` | `Connection to <vm-ip> 4822 port [tcp/*] succeeded` |
| 9.2 | Port 22 reachable from any IP | `nc -zv <vm-ip> 22` | `Connection succeeded` (nothing listens yet — nc will connect and hang briefly, which proves the port is open) |
| 9.3 | Port 23 reachable from any IP | `nc -zv <vm-ip> 23` | `Connection succeeded` |
| 9.4 | Port 22 is NOT answered by real sshd | `ssh -p 22 ubuntu@<vm-ip>` | Connection refused or no SSH banner (cowrie not yet running in Phase 1) OR confirms sshd is not on 22 |

---

## 10. Summary Sign-Off

Complete all items above. Then sign off:

```
Phase 1 verified by: ___________________________
Date:                ___________________________
VM public IP:        ___________________________
All items green?     [ ] Yes — proceed to Phase 2
                     [ ] No  — items pending: ___________________________
```

---

## Quick Reference: Most Likely Failure Modes

| Symptom | Most Likely Cause | Fix |
|---------|------------------|-----|
| Port 23 connection refused from internet | OCI Security List missing rule for 23 | Add ingress rule per `oci_security_list.md` |
| Port 23 open but traffic doesn't reach cowrie | OCI default iptables not flushed (Step 4 skipped) | Re-run setup_host.sh, confirm Step 4 |
| SSH to port 4822 refused | Fail2ban banned your IP, or Security List missing | `sudo fail2ban-client status greyfield-admin-ssh` — unban if needed |
| PREROUTING rules gone after reboot | netfilter-persistent not saved or disabled | `sudo netfilter-persistent save && sudo systemctl enable netfilter-persistent` |
| `fail2ban-client status greyfield-admin-ssh` returns error | Jail config syntax error | `sudo fail2ban-client reload` and check `/var/log/fail2ban.log` |
