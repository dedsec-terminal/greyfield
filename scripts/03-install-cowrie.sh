#!/usr/bin/env bash
set -Eeuo pipefail

readonly COWRIE_VERSION=${COWRIE_VERSION:-3.0.13}
readonly HONEYPOT_DIR=${HONEYPOT_DIR:-${HOME}/honeypot}
readonly REPO_DIR=${REPO_DIR:-/opt/greyfield}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[greyfield] %s\n' "$*"; }

[[ $(id -un) == cowrie ]] ||
  die "Run with: sudo -u cowrie -H bash /opt/greyfield/scripts/03-install-cowrie.sh"
[[ -f ${REPO_DIR}/configs/cowrie.cfg ]] || die "Greyfield configuration is missing."

python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' ||
  die "Cowrie requires Python 3.10 or newer."

mkdir -p "${HONEYPOT_DIR}"
cd "${HONEYPOT_DIR}"

if [[ ! -d cowrie-env ]]; then
  log "Creating Python virtual environment"
  python3 -m venv cowrie-env
fi

# shellcheck source=/dev/null
source cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install "cowrie==${COWRIE_VERSION}"

if [[ ! -f etc/cowrie.cfg ]]; then
  cowrie init
else
  cp etc/cowrie.cfg "etc/cowrie.cfg.pre-greyfield.$(date -u +%Y%m%dT%H%M%SZ).bak"
fi
cp "${REPO_DIR}/configs/cowrie.cfg" etc/cowrie.cfg

if cowrie status >/dev/null 2>&1; then
  cowrie stop
fi
cowrie start
sleep 3
cowrie status

ss -tlnp | grep -qE ':(2222|2323)\b' || {
  tail -n 80 var/log/cowrie/cowrie.log >&2 || true
  die "Cowrie listeners are not available."
}

log "Cowrie ${COWRIE_VERSION} installed"
ss -tlnp | grep -E ':(2222|2323)\b'
