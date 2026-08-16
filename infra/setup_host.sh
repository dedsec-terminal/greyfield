#!/usr/bin/env bash
# =============================================================================
# Greyfield — Phase 1 Host Hardening Script
# Target:  Oracle Cloud Ubuntu 24.04 LTS (VM.Standard.E2.1.Micro)
# Author:  <your-name>
# Version: 1.0.0
#
# USAGE
#   sudo bash setup_host.sh
#
# WHAT THIS SCRIPT DOES (in order)
#   1.  System package update & upgrade
#   2.  Create the 'cowrie' system user (no login shell)
#   3.  Move SSH admin port from 22 → 4822
#   4.  Flush OCI default iptables rules (their end-of-chain REJECT silently
#       drops 23/tcp and any PREROUTING redirects we add)
#   5.  Install and configure UFW (4822 admin, 22+23 honeypot, 443 git push,
#       80 dashboard)
#   6.  Install and configure Fail2ban on port 4822
#   7.  Add iptables PREROUTING redirects (22→2222, 23→2223)
#   8.  Persist all rules via netfilter-persistent
#
# CONFIRMATION GATES
#   Every irreversible step prompts y/N before executing.
#   Answering anything other than 'y' (case-insensitive) skips the step.
#
# SAFETY NOTES
#   • Run this over an OCI Cloud Shell or console connection, not just SSH,
#     the first time — the SSH port change will drop your existing session.
#   • After step 3 completes, reconnect on port 4822.
#   • Do NOT run Phase 2 (Cowrie) until this script exits cleanly.
# =============================================================================

set -euo pipefail

# ─── Color helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

banner()  { echo -e "\n${CYN}${BLD}════════════════════════════════════════${RST}"; \
            echo -e "${CYN}${BLD}  $1${RST}"; \
            echo -e "${CYN}${BLD}════════════════════════════════════════${RST}"; }
info()    { echo -e "${GRN}[INFO]${RST}  $*"; }
warn()    { echo -e "${YLW}[WARN]${RST}  $*"; }
err()     { echo -e "${RED}[ERROR]${RST} $*" >&2; }
step()    { echo -e "\n${BLD}── STEP $1: $2 ──${RST}"; }

# ─── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  err "This script must be run as root (use: sudo bash setup_host.sh)"
  exit 1
fi

# ─── Confirmation gate ────────────────────────────────────────────────────────
# Usage: confirm "description of irreversible action"
# Returns 0 (proceed) or 1 (skip).
confirm() {
  local msg="$1"
  echo -e "\n${YLW}[CONFIRM]${RST} About to: ${BLD}${msg}${RST}"
  echo -e "          This action is ${RED}irreversible${RST}."
  read -rp "          Proceed? [y/N]: " ans
  case "${ans}" in
    [yY]) return 0 ;;
    *)    warn "Skipped: ${msg}"; return 1 ;;
  esac
}

# ─── Soft confirmation gate (reversible steps) ────────────────────────────────
confirm_soft() {
  local msg="$1"
  echo -e "\n${GRN}[CONFIRM]${RST} About to: ${BLD}${msg}${RST}"
  read -rp "          Proceed? [y/N]: " ans
  case "${ans}" in
    [yY]) return 0 ;;
    *)    warn "Skipped: ${msg}"; return 1 ;;
  esac
}

# ─── Track what we've done ────────────────────────────────────────────────────
STEPS_DONE=()
STEPS_SKIPPED=()

mark_done()    { STEPS_DONE+=("$1"); }
mark_skipped() { STEPS_SKIPPED+=("$1"); }

# =============================================================================
# MAIN
# =============================================================================

banner "Greyfield — Phase 1 Host Hardening"
echo ""
echo "  VM shape  : Oracle Cloud VM.Standard.E2.1.Micro"
echo "  OS        : Ubuntu 24.04 LTS"
echo "  Admin SSH : 4822"
echo "  Honeypot  : 22 (SSH) → 2222, 23 (Telnet) → 2223"
echo ""
warn "Read each confirmation prompt carefully. SSH port will change mid-run."
warn "Keep an OCI Cloud Shell / console session open as a fallback."
echo ""

# =============================================================================
# STEP 1 — Package update & upgrade
# =============================================================================
step 1 "System package update & upgrade"

if confirm_soft "Run apt update && apt upgrade -y (will download packages)"; then
  apt-get update -y
  apt-get upgrade -y
  apt-get autoremove -y
  # Install all dependencies we need across this script in one shot
  apt-get install -y \
    ufw \
    fail2ban \
    netfilter-persistent \
    iptables-persistent \
    curl \
    git \
    python3-venv \
    python3-pip
  mark_done "Step 1: Package update"
  info "Packages updated and dependencies installed."
else
  mark_skipped "Step 1: Package update"
  warn "Skipping package update — subsequent steps may fail if dependencies are missing."
fi

# =============================================================================
# STEP 2 — Create 'cowrie' system user
# =============================================================================
step 2 "Create 'cowrie' system user (no login shell)"

if id cowrie &>/dev/null; then
  info "User 'cowrie' already exists — skipping creation."
  mark_done "Step 2: cowrie user (pre-existing)"
else
  if confirm_soft "Create system user 'cowrie' with /sbin/nologin shell"; then
    useradd \
      --system \
      --no-create-home \
      --shell /sbin/nologin \
      --comment "Cowrie honeypot service account" \
      cowrie
    info "User 'cowrie' created:"
    id cowrie
    mark_done "Step 2: cowrie user"
  else
    mark_skipped "Step 2: cowrie user"
    warn "Cowrie user not created — Phase 2 will fail without it."
  fi
fi

# =============================================================================
# STEP 3 — Move SSH admin port from 22 → 4822
#
# !! IRREVERSIBLE in the sense that once sshd restarts on 4822, any existing
#    session on port 22 will be the last one. !!
# =============================================================================
step 3 "Move SSH admin port from 22 → 4822"

SSHD_CONF="/etc/ssh/sshd_config"
CURRENT_PORT=$(grep -E "^Port " "${SSHD_CONF}" 2>/dev/null | awk '{print $2}' || echo "22")
info "Current sshd Port directive: ${CURRENT_PORT}"

if [[ "${CURRENT_PORT}" == "4822" ]]; then
  info "SSH is already configured on port 4822 — skipping."
  mark_done "Step 3: SSH port (already 4822)"
else
  echo ""
  echo -e "  ${RED}${BLD}⚠  WARNING — SESSION IMPACT  ⚠${RST}"
  echo "  After this step, sshd will restart on port 4822."
  echo "  Your current SSH session (if on port 22) WILL be disconnected."
  echo "  Ensure you have OCI Cloud Shell / console access before proceeding."
  echo "  Reconnect command: ssh -p 4822 ubuntu@<your-ip>"
  echo ""

  if confirm "Change SSH Port from ${CURRENT_PORT} to 4822 and restart sshd"; then
    # Back up original config
    cp "${SSHD_CONF}" "${SSHD_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    info "Backed up ${SSHD_CONF}"

    # Remove any existing Port lines, then add the new one
    sed -i 's/^#\?Port .*//' "${SSHD_CONF}"
    echo "Port 4822" >> "${SSHD_CONF}"

    # Harden SSH while we're here
    # (only set these if not already present — append-safe)
    grep -qE "^PermitRootLogin" "${SSHD_CONF}" \
      && sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "${SSHD_CONF}" \
      || echo "PermitRootLogin no" >> "${SSHD_CONF}"

    grep -qE "^PasswordAuthentication" "${SSHD_CONF}" \
      && sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "${SSHD_CONF}" \
      || echo "PasswordAuthentication no" >> "${SSHD_CONF}"

    grep -qE "^X11Forwarding" "${SSHD_CONF}" \
      && sed -i 's/^X11Forwarding.*/X11Forwarding no/' "${SSHD_CONF}" \
      || echo "X11Forwarding no" >> "${SSHD_CONF}"

    grep -qE "^MaxAuthTries" "${SSHD_CONF}" \
      && sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' "${SSHD_CONF}" \
      || echo "MaxAuthTries 3" >> "${SSHD_CONF}"

    # Validate config before restarting
    if sshd -t; then
      systemctl restart sshd
      info "sshd restarted on port 4822."
      info "Reconnect: ssh -p 4822 ubuntu@<your-vm-public-ip>"
      mark_done "Step 3: SSH port → 4822"
    else
      err "sshd config validation failed! Restoring backup..."
      cp "${SSHD_CONF}.bak."* "${SSHD_CONF}" 2>/dev/null || true
      mark_skipped "Step 3: SSH port (config error — backup restored)"
      exit 1
    fi
  else
    mark_skipped "Step 3: SSH port"
  fi
fi

# =============================================================================
# STEP 4 — Flush OCI default iptables rules
#
# Oracle Cloud Ubuntu images ship with default iptables rules that include an
# end-of-chain REJECT target in the INPUT and FORWARD chains. This silently
# drops port 23/tcp (Telnet) and prevents any PREROUTING redirect we add from
# working, because the packet is rejected before it reaches the honeypot.
#
# We flush those rules here. UFW re-establishes a clean, explicit policy in
# the next step.
#
# !! IRREVERSIBLE: OCI's default rules are not recoverable without a reimage
#    (though UFW will replace them with correct rules immediately after). !!
# =============================================================================
step 4 "Flush OCI default iptables rules"

echo ""
echo "  OCI Ubuntu images ship with iptables rules that include a default"
echo "  REJECT at the end of INPUT/FORWARD. This silently drops:"
echo "    • port 23/tcp (Telnet) — honeypot capture will be dead without flushing"
echo "    • any PREROUTING redirects we add in Step 7"
echo "  Flushing replaces them with ACCEPT-all. UFW (Step 5) then re-establishes"
echo "  a correct, explicit policy immediately after."
echo ""

if confirm "Flush all iptables rules (IPv4 and IPv6) — OCI default REJECT removed"; then
  # IPv4
  iptables -F                  # Flush all chains
  iptables -X                  # Delete user-defined chains
  iptables -t nat -F           # Flush nat table (clears any stale PREROUTING)
  iptables -t nat -X
  iptables -t mangle -F
  iptables -t mangle -X
  iptables -P INPUT ACCEPT     # Set default policy to ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  # IPv6 (mirror, to avoid asymmetric behavior)
  ip6tables -F
  ip6tables -X
  ip6tables -t nat -F 2>/dev/null || true   # ip6tables nat may not exist on all kernels
  ip6tables -t nat -X 2>/dev/null || true
  ip6tables -t mangle -F
  ip6tables -t mangle -X
  ip6tables -P INPUT ACCEPT
  ip6tables -P FORWARD ACCEPT
  ip6tables -P OUTPUT ACCEPT

  info "iptables flushed. Current IPv4 ruleset:"
  iptables -L -n -v --line-numbers
  mark_done "Step 4: iptables flush"
else
  mark_skipped "Step 4: iptables flush"
  warn "OCI default REJECT rules still in place — Telnet honeypot will NOT work."
fi

# =============================================================================
# STEP 5 — UFW configuration
#
# Port policy:
#   4822/tcp  — admin SSH (rate-limited)
#   22/tcp    — honeypot SSH  (allow, PREROUTING will redirect to cowrie:2222)
#   23/tcp    — honeypot Telnet (allow, PREROUTING will redirect to cowrie:2223)
#   443/tcp   — outbound for git push / GitHub Pages deploy
#   80/tcp    — dashboard (you'll restrict this to your IP via OCI Security List)
# =============================================================================
step 5 "UFW configuration"

if confirm_soft "Configure UFW with honeypot + admin rules"; then
  # Disable UFW first so we can configure it cleanly without locking ourselves out
  ufw --force disable 2>/dev/null || true

  # Reset to defaults (removes any prior rules)
  ufw --force reset

  # Default policies
  ufw default deny incoming
  ufw default allow outgoing

  # Admin SSH — rate-limited (max 6 connections per 30 seconds from same IP)
  ufw limit 4822/tcp comment "Admin SSH (rate-limited)"

  # Honeypot ports — full allow (attackers must reach these)
  ufw allow 22/tcp  comment "Honeypot SSH (redirected to cowrie:2222)"
  ufw allow 23/tcp  comment "Honeypot Telnet (redirected to cowrie:2223)"

  # HTTPS — outbound for GitHub Pages push and API calls (covered by default allow,
  # but listed here for documentation clarity via explicit rule)
  ufw allow out 443/tcp comment "HTTPS outbound: git push / API calls"

  # Dashboard — HTTP (lock this down to your IP in OCI Security List separately)
  ufw allow 80/tcp  comment "Dashboard HTTP (restrict in OCI Security List)"

  # Enable UFW
  ufw --force enable

  info "UFW status:"
  ufw status verbose
  mark_done "Step 5: UFW"
else
  mark_skipped "Step 5: UFW"
  warn "No UFW rules applied — host is unprotected."
fi

# =============================================================================
# STEP 6 — Fail2ban on port 4822
# =============================================================================
step 6 "Fail2ban — protect admin SSH on port 4822"

if confirm_soft "Install Fail2ban jail for port 4822"; then

  # Write the Greyfield-specific jail config
  cat > /etc/fail2ban/jail.d/greyfield-admin-ssh.conf << 'EOF'
[greyfield-admin-ssh]
enabled   = true
port      = 4822
filter    = sshd
logpath   = /var/log/auth.log
maxretry  = 3
findtime  = 600
bantime   = 3600
action    = iptables-multiport[name=greyfield-admin, port="4822", protocol=tcp]
            %(mwl)s
EOF

  # Ensure fail2ban service is enabled and running
  systemctl enable fail2ban
  systemctl restart fail2ban

  info "Fail2ban status for greyfield-admin-ssh jail:"
  fail2ban-client status greyfield-admin-ssh 2>/dev/null || \
    warn "Jail not yet visible — fail2ban may need a moment to load jails."

  mark_done "Step 6: Fail2ban"
else
  mark_skipped "Step 6: Fail2ban"
  warn "Admin SSH port 4822 is not brute-force protected."
fi

# =============================================================================
# STEP 7 — iptables PREROUTING redirects
#
# Redirect packets arriving on port 22/tcp → localhost:2222 (cowrie SSH listener)
# Redirect packets arriving on port 23/tcp → localhost:2223 (cowrie Telnet listener)
#
# These rules go into the nat table PREROUTING chain. They must be applied
# AFTER the iptables flush (Step 4) so they aren't wiped by it.
#
# Cowrie itself binds to 2222/2223 and runs as the unprivileged 'cowrie' user.
# Non-root processes cannot bind to ports <1024 directly.
# =============================================================================
step 7 "iptables PREROUTING redirects (22→2222, 23→2223)"

echo ""
echo "  These redirects send attacker traffic to cowrie's unprivileged ports."
echo "  22/tcp  → 127.0.0.1:2222  (cowrie SSH)"
echo "  23/tcp  → 127.0.0.1:2223  (cowrie Telnet)"
echo ""

if confirm "Add iptables PREROUTING REDIRECT rules for ports 22 and 23"; then

  # Remove any pre-existing duplicate rules before adding
  iptables -t nat -D PREROUTING -p tcp --dport 22  -j REDIRECT --to-port 2222 2>/dev/null || true
  iptables -t nat -D PREROUTING -p tcp --dport 23  -j REDIRECT --to-port 2223 2>/dev/null || true

  # Add fresh rules
  iptables -t nat -A PREROUTING -p tcp --dport 22  -j REDIRECT --to-port 2222
  iptables -t nat -A PREROUTING -p tcp --dport 23  -j REDIRECT --to-port 2223

  info "Current nat PREROUTING chain:"
  iptables -t nat -L PREROUTING -n -v --line-numbers

  mark_done "Step 7: PREROUTING redirects"
else
  mark_skipped "Step 7: PREROUTING redirects"
  warn "No PREROUTING redirects — cowrie will NOT receive attacker traffic."
fi

# =============================================================================
# STEP 8 — Persist rules via netfilter-persistent
#
# Saves all current iptables/ip6tables rules so they survive reboot.
# =============================================================================
step 8 "Persist iptables rules via netfilter-persistent"

if confirm_soft "Save all iptables rules to /etc/iptables/rules.v4 and rules.v6"; then

  # netfilter-persistent save writes to /etc/iptables/rules.v{4,6}
  netfilter-persistent save

  info "Saved rules:"
  echo "  IPv4: /etc/iptables/rules.v4"
  cat /etc/iptables/rules.v4
  echo ""
  echo "  IPv6: /etc/iptables/rules.v6"
  cat /etc/iptables/rules.v6

  # Ensure the service is enabled so rules reload on boot
  systemctl enable netfilter-persistent

  mark_done "Step 8: netfilter-persistent"
else
  mark_skipped "Step 8: netfilter-persistent"
  warn "Rules NOT persisted — will be lost on next reboot."
fi

# =============================================================================
# SUMMARY
# =============================================================================
banner "Phase 1 Complete — Summary"
echo ""
echo -e "${GRN}Completed steps:${RST}"
for s in "${STEPS_DONE[@]+"${STEPS_DONE[@]}"}"; do
  echo "  ✔ ${s}"
done

if [[ ${#STEPS_SKIPPED[@]} -gt 0 ]]; then
  echo ""
  echo -e "${YLW}Skipped steps (action required before Phase 2):${RST}"
  for s in "${STEPS_SKIPPED[@]}"; do
    echo "  ✗ ${s}"
  done
fi

echo ""
echo "────────────────────────────────────────────────────────────"
echo -e "${BLD}Next actions (manual):${RST}"
echo "  1. Open OCI Security List ingress for 22, 23, 4822"
echo "     (see infra/oci_security_list.md)"
echo "  2. Reconnect via SSH on port 4822:"
echo "     ssh -p 4822 ubuntu@<your-vm-public-ip>"
echo "  3. Verify ports are reachable (see docs/HARDENING_CHECKLIST.md)"
echo "  4. Proceed to Phase 2: Cowrie deployment"
echo "────────────────────────────────────────────────────────────"
echo ""
