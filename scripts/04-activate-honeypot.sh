#!/usr/bin/env bash
set -Eeuo pipefail

readonly ADMIN_PORT=2223
readonly COWRIE_SSH_PORT=2222
readonly COWRIE_TELNET_PORT=2323
readonly REPO_DIR=/opt/greyfield

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[greyfield] %s\n' "$*"; }

[[ ${EUID} -ne 0 ]] || die "Run as the normal OCI user, not root."
sudo -n true || die "The current user requires passwordless sudo access."

printf 'Have you successfully logged in from a SECOND terminal on port %s? [y/N] ' "${ADMIN_PORT}"
read -r reply
[[ ${reply} =~ ^[Yy]$ ]] || die "Activation refused until administrator SSH is proven."

sudo ss -tlnp | grep -q ":${ADMIN_PORT} " || die "Real SSH is not listening on ${ADMIN_PORT}."
sudo ss -tlnp | grep -q ":${COWRIE_SSH_PORT} " || die "Cowrie SSH listener is missing."
sudo ss -tlnp | grep -q ":${COWRIE_TELNET_PORT} " || die "Cowrie Telnet listener is missing."

sudo cp "${REPO_DIR}/systemd/cowrie.service" /etc/systemd/system/cowrie.service
sudo systemctl daemon-reload
sudo systemctl enable cowrie >/dev/null

# Replace the manual Cowrie process with the systemd-managed process.
sudo -u cowrie -H bash -lc 'cd ~/honeypot && source cowrie-env/bin/activate && cowrie stop' || true
sudo systemctl restart cowrie
sleep 3
sudo systemctl is-active --quiet cowrie || die "cowrie.service failed to start."

add_redirect() {
  local from_port=$1
  local to_port=$2
  if ! sudo iptables -t nat -C PREROUTING -p tcp --dport "${from_port}" -j REDIRECT --to-port "${to_port}" 2>/dev/null; then
    sudo iptables -t nat -A PREROUTING -p tcp --dport "${from_port}" -j REDIRECT --to-port "${to_port}"
  fi
}

add_redirect 22 "${COWRIE_SSH_PORT}"
add_redirect 23 "${COWRIE_TELNET_PORT}"
sudo netfilter-persistent save >/dev/null

# UFW sees the rewritten destination ports after NAT PREROUTING.
sudo ufw delete allow 22/tcp >/dev/null 2>&1 || true

sudo tee /etc/fail2ban/jail.d/greyfield-sshd.local >/dev/null <<EOF
[sshd]
enabled = true
port = ${ADMIN_PORT}
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 3
EOF
sudo systemctl enable --now fail2ban >/dev/null
sudo systemctl restart fail2ban
sudo passwd -l root >/dev/null

log "Greyfield activation complete"
sudo systemctl --no-pager --full status cowrie | sed -n '1,12p'
sudo ufw status numbered
sudo iptables -t nat -S PREROUTING
