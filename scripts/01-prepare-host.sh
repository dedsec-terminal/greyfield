#!/usr/bin/env bash
set -Eeuo pipefail

readonly ADMIN_PORT=2223
readonly COWRIE_SSH_PORT=2222
readonly COWRIE_TELNET_PORT=2323

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[greyfield] %s\n' "$*"; }

valid_ipv4() {
  local address=$1 octet
  local -a octets
  [[ ${address} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a octets <<<"${address}"
  for octet in "${octets[@]}"; do
    (( 10#${octet} <= 255 )) || return 1
  done
}

[[ ${EUID} -ne 0 ]] || die "Run as the normal OCI user, not root."
sudo -n true || die "The current user requires passwordless sudo access."

# shellcheck source=/dev/null
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 22.04 ]] ||
  die "Supported baseline is Ubuntu 22.04; found ${PRETTY_NAME:-unknown}."
[[ $(uname -m) == x86_64 ]] || die "Supported baseline is x86_64."

# SSH_CONNECTION begins with the client address. An explicit ADMIN_IP is only
# needed when this stage is run from a serial console instead of over SSH.
ADMIN_IP=${ADMIN_IP:-${SSH_CONNECTION%% *}}
valid_ipv4 "${ADMIN_IP}" ||
  die "Cannot determine a valid administrator IPv4. Run with ADMIN_IP=x.x.x.x."
log "Restricting host-side administrator SSH to ${ADMIN_IP}/32"

export DEBIAN_FRONTEND=noninteractive
log "Updating Ubuntu packages"
sudo -E apt-get update
sudo -E apt-get upgrade -y

printf '%s\n' \
  'iptables-persistent iptables-persistent/autosave_v4 boolean false' \
  'iptables-persistent iptables-persistent/autosave_v6 boolean false' |
  sudo debconf-set-selections

log "Installing host dependencies"
sudo -E apt-get install -y \
  python3-pip python3-venv python3-dev \
  libssl-dev libffi-dev build-essential \
  git ufw fail2ban iptables-persistent

if [[ ! -f /swapfile ]]; then
  log "Creating 2 GB swap file"
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile >/dev/null
fi
if ! sudo swapon --show=NAME --noheadings | grep -qx '/swapfile'; then
  sudo swapon /swapfile
fi
if ! grep -qF '/swapfile none swap sw 0 0' /etc/fstab; then
  printf '%s\n' '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

if ! id cowrie >/dev/null 2>&1; then
  log "Creating unprivileged cowrie service account"
  sudo adduser --disabled-password --gecos '' cowrie
fi

if sudo iptables -S INPUT | grep -q -- '-j REJECT'; then
  printf 'Oracle REJECT rules detected. Clear them before enabling UFW? [y/N] '
  read -r reply
  [[ ${reply} =~ ^[Yy]$ ]] || die "Aborted without changing firewall rules."
  sudo iptables -P INPUT ACCEPT
  sudo iptables -P FORWARD ACCEPT
  sudo iptables -F INPUT
  sudo iptables -F FORWARD
fi

log "Configuring UFW while preserving the current port-22 session"
sudo ufw --force reset >/dev/null
sudo ufw default deny incoming >/dev/null
sudo ufw default allow outgoing >/dev/null
sudo ufw allow 22/tcp comment 'TEMP real SSH until activation' >/dev/null
sudo ufw allow from "${ADMIN_IP}" to any port "${ADMIN_PORT}" proto tcp comment 'Greyfield admin SSH' >/dev/null
sudo ufw allow "${COWRIE_SSH_PORT}/tcp" comment 'Cowrie SSH after redirect' >/dev/null
sudo ufw allow "${COWRIE_TELNET_PORT}/tcp" comment 'Cowrie Telnet after redirect' >/dev/null
sudo ufw --force enable >/dev/null

sudo iptables -S INPUT | grep -q 'ufw' || {
  sudo iptables -P INPUT ACCEPT
  die "UFW did not attach to INPUT; policy restored to ACCEPT."
}

log "Preparation complete"
sudo swapon --show
sudo ufw status verbose
if [[ -f /var/run/reboot-required ]]; then
  log "Ubuntu reports that a reboot is required. Reboot before Stage 2."
fi
