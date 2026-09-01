#!/usr/bin/env bash
set -Eeuo pipefail

readonly ADMIN_PORT=2223
readonly DROP_IN=/etc/ssh/sshd_config.d/00-greyfield.conf
readonly ADMIN_USER=${ADMIN_USER:-$(id -un)}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[greyfield] %s\n' "$*"; }

[[ ${EUID} -ne 0 ]] || die "Run as the normal OCI user, not root."
sudo -n true || die "The current user requires passwordless sudo access."
[[ ${ADMIN_USER} =~ ^[a-z_][a-z0-9_-]*$ ]] || die "Unsafe administrator user name."

sudo ufw status | grep -q "${ADMIN_PORT}/tcp" ||
  die "UFW does not allow ${ADMIN_PORT}/tcp. Run Stage 1 first."

if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  die "ssh.socket is enabled. This baseline expects Ubuntu 22.04 ssh.service."
fi

printf 'Confirm OCI allows TCP %s from your current public /32 [y/N] ' "${ADMIN_PORT}"
read -r reply
[[ ${reply} =~ ^[Yy]$ ]] || die "Aborted before changing SSH."

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
sudo cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.greyfield.${timestamp}.bak"

sudo tee "${DROP_IN}" >/dev/null <<EOF
Port ${ADMIN_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers ${ADMIN_USER}
UsePAM yes
EOF

sudo sshd -t || {
  sudo rm -f "${DROP_IN}"
  die "OpenSSH rejected the configuration; the drop-in was removed."
}

effective_ports=$(sudo sshd -T | awk '/^port /{print $2}' | sort -u | tr '\n' ' ')
[[ ${effective_ports} == "${ADMIN_PORT} " ]] || {
  sudo rm -f "${DROP_IN}"
  die "Unexpected effective SSH ports: ${effective_ports}"
}

log "Restarting real SSH on ${ADMIN_PORT}"
sudo systemctl restart ssh
sleep 2
sudo ss -tlnp | grep -q ":${ADMIN_PORT} " ||
  die "sshd is not listening on ${ADMIN_PORT}. Keep this session open."

cat <<EOF

Real SSH is listening on ${ADMIN_PORT}.
KEEP THIS SESSION OPEN.

From a second terminal, test:
  ssh -i <private-key> -p ${ADMIN_PORT} ${ADMIN_USER}@<public-ip>

If it fails, rollback from this still-open session:
  sudo rm -f ${DROP_IN}
  sudo systemctl restart ssh

Do not run Stage 4 until the independent login succeeds.
EOF
