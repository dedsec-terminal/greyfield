#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG_FILE="${GREYFIELD_DASHBOARD_CONFIG:-/etc/greyfield-dashboard/config}"
readonly DEFAULT_LOG_FILE="/home/cowrie/honeypot/var/log/cowrie/cowrie.json"
readonly DEFAULT_EXPORTER="/opt/greyfield/scripts/export-dashboard.py"
readonly DEFAULT_VALIDATOR="/opt/greyfield/scripts/validate-dashboard.py"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root_private_file() {
  local path="$1"
  [[ -f "$path" ]] || die "Required file does not exist: $path"
  [[ "$(stat -c '%u' "$path")" == "0" ]] || die "File must be owned by root: $path"
  local mode
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 8#022) == 0 )) || die "File must not be writable by group or others: $path"
}

[[ "${EUID}" == "0" ]] || die "Run this publisher as root."
require_root_private_file "$CONFIG_FILE"

# The config is an administrator-owned shell assignment file. Its ownership and
# write permissions are checked before sourcing it.
# shellcheck source=/dev/null
source "$CONFIG_FILE"

: "${REPO_SSH:?Set REPO_SSH in $CONFIG_FILE}"
: "${DEPLOY_KEY:?Set DEPLOY_KEY in $CONFIG_FILE}"
: "${KNOWN_HOSTS:?Set KNOWN_HOSTS in $CONFIG_FILE}"

LOG_FILE="${LOG_FILE:-$DEFAULT_LOG_FILE}"
EXPORTER="${EXPORTER:-$DEFAULT_EXPORTER}"
VALIDATOR="${VALIDATOR:-$DEFAULT_VALIDATOR}"
SENSOR_NAME="${SENSOR_NAME:-greyfield-honeypot}"
SENSOR_STATUS="${SENSOR_STATUS:-operational}"
REGION="${REGION:-unknown}"
PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-}"
EXCLUDE_IPS="${EXCLUDE_IPS:-}"
GEO_CACHE="${GEO_CACHE:-/var/lib/greyfield-dashboard/geo-cache.json}"
GEO_LIMIT="${GEO_LIMIT:-40}"
ENRICHMENT_PROVIDERS="${ENRICHMENT_PROVIDERS:-}"
ENRICHMENT_CACHE="${ENRICHMENT_CACHE:-/var/lib/greyfield-dashboard/enrichment-cache.json}"
MALWAREBAZAAR_AUTH_KEY_FILE="${MALWAREBAZAAR_AUTH_KEY_FILE:-}"
VIRUSTOTAL_API_KEY_FILE="${VIRUSTOTAL_API_KEY_FILE:-}"
PROVIDER_LIMIT="${PROVIDER_LIMIT:-3}"

require_root_private_file "$DEPLOY_KEY"
require_root_private_file "$KNOWN_HOSTS"
[[ -r "$LOG_FILE" ]] || die "Cowrie log is not readable: $LOG_FILE"
[[ -f "$EXPORTER" ]] || die "Exporter is missing: $EXPORTER"
[[ -f "$VALIDATOR" ]] || die "Validator is missing: $VALIDATOR"

work_dir="$(mktemp -d /tmp/greyfield-telemetry.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

export GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS"

repo_dir="$work_dir/repository"
if git ls-remote --exit-code --heads "$REPO_SSH" telemetry >/dev/null 2>&1; then
  git clone --quiet --depth 1 --single-branch --branch telemetry "$REPO_SSH" "$repo_dir"
else
  mkdir -p "$repo_dir"
  git -C "$repo_dir" init --quiet
  git -C "$repo_dir" checkout --quiet --orphan telemetry
  git -C "$repo_dir" remote add origin "$REPO_SSH"
fi

# The telemetry branch is an intentionally minimal publication boundary. Remove
# any previously tracked content before recreating its two allowed artifacts.
git -C "$repo_dir" rm -r -q --ignore-unmatch .

exclude_args=()
deny_args=()
endpoint_args=()
enrichment_args=()
if [[ -n "$EXCLUDE_IPS" ]]; then
  read -r -a exclude_ip_list <<<"$EXCLUDE_IPS"
  for address in "${exclude_ip_list[@]}"; do
    exclude_args+=(--exclude-ip "$address")
    deny_args+=(--deny-ip "$address")
  done
fi
if [[ -n "$PUBLIC_ENDPOINT" ]]; then
  endpoint_args+=(--public-endpoint "$PUBLIC_ENDPOINT")
fi
if [[ -n "$ENRICHMENT_PROVIDERS" ]]; then
  read -r -a provider_list <<<"$ENRICHMENT_PROVIDERS"
  enrichment_args+=(--enrichment-cache "$ENRICHMENT_CACHE" --provider-limit "$PROVIDER_LIMIT")
  for provider in "${provider_list[@]}"; do
    case "$provider" in
      malwarebazaar)
        [[ -n "$MALWAREBAZAAR_AUTH_KEY_FILE" ]] || die "Set MALWAREBAZAAR_AUTH_KEY_FILE when malwarebazaar is enabled."
        require_root_private_file "$MALWAREBAZAAR_AUTH_KEY_FILE"
        enrichment_args+=(--enrichment-provider malwarebazaar --malwarebazaar-auth-key-file "$MALWAREBAZAAR_AUTH_KEY_FILE")
        ;;
      virustotal)
        [[ -n "$VIRUSTOTAL_API_KEY_FILE" ]] || die "Set VIRUSTOTAL_API_KEY_FILE when virustotal is enabled."
        require_root_private_file "$VIRUSTOTAL_API_KEY_FILE"
        enrichment_args+=(--enrichment-provider virustotal --virustotal-api-key-file "$VIRUSTOTAL_API_KEY_FILE")
        ;;
      *)
        die "Unsupported enrichment provider: $provider"
        ;;
    esac
  done
fi

python3 "$EXPORTER" \
  --log "$LOG_FILE" \
  --output "$repo_dir/metrics.json" \
  --layer-output "$repo_dir/attack-layer.json" \
  --sensor-name "$SENSOR_NAME" \
  --sensor-status "$SENSOR_STATUS" \
  --region "$REGION" \
  --geo-cache "$GEO_CACHE" \
  --geo-limit "$GEO_LIMIT" \
  "${endpoint_args[@]}" \
  "${enrichment_args[@]}" \
  "${exclude_args[@]}"

python3 "$VALIDATOR" "$repo_dir/metrics.json" \
  --layer "$repo_dir/attack-layer.json" \
  "${deny_args[@]}"

git -C "$repo_dir" add -- metrics.json attack-layer.json
if git -C "$repo_dir" diff --cached --quiet; then
  printf 'Telemetry is unchanged; nothing to publish.\n'
  exit 0
fi

git -C "$repo_dir" config user.name "Greyfield Telemetry"
git -C "$repo_dir" config user.email "telemetry@localhost"
git -C "$repo_dir" commit --quiet -m "telemetry: publish reviewed evidence snapshot"
git -C "$repo_dir" push --quiet origin HEAD:telemetry
printf 'Published a reviewed Greyfield evidence snapshot.\n'
