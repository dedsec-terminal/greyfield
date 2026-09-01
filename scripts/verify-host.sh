#!/usr/bin/env bash
set -Eeuo pipefail

failures=0
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }

check_command() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "${description}"; else fail "${description}"; fi
}

# shellcheck source=/dev/null
source /etc/os-release
if [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 22.04 ]]; then
  pass "Ubuntu 22.04 baseline"
else
  fail "Ubuntu 22.04 baseline"
fi
if [[ $(uname -m) == x86_64 ]]; then
  pass "x86-64 architecture"
else
  fail "x86-64 architecture"
fi
check_command "2 GB swap is active" bash -c "swapon --show=NAME --noheadings | grep -qx '/swapfile'"
check_command "UFW is active" bash -c "sudo ufw status | grep -q '^Status: active$'"
check_command "real SSH listens on 2223" bash -c "sudo ss -tlnp | grep -q ':2223 '"
check_command "Cowrie SSH listens on 2222" bash -c "sudo ss -tlnp | grep -q ':2222 '"
check_command "Cowrie Telnet listens on 2323" bash -c "sudo ss -tlnp | grep -q ':2323 '"
check_command "cowrie.service is active" sudo systemctl is-active --quiet cowrie
check_command "fail2ban.service is active" sudo systemctl is-active --quiet fail2ban
check_command "SSH redirect persists" sudo iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
check_command "Telnet redirect persists" sudo iptables -t nat -C PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
check_command "Cowrie JSON log exists" sudo test -f /home/cowrie/honeypot/var/log/cowrie/cowrie.json

printf '\nUFW rules:\n'
sudo ufw status numbered || true
printf '\nNAT rules:\n'
sudo iptables -t nat -S PREROUTING || true

if (( failures > 0 )); then
  printf '\nVerification failed: %d check(s)\n' "${failures}" >&2
  exit 1
fi
printf '\nAll Greyfield host checks passed.\n'
