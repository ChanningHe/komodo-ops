#!/usr/bin/env bash
# Fail if any address/domain stored in komodo-secrets, a private IPv4, or an IPv6 literal appears under PATH.
# This repo is public: run before committing dashboards or other exported configs.
# Only file names are printed, never the matched value.
#
#   ./check-leaks.sh                          # default: stacks/poecilia/grafana
#   ./check-leaks.sh stacks/poecilia/victoria
set -euo pipefail

cd "$(dirname "$0")"
target="${1:-stacks/poecilia/grafana}"
# generic ranges that are fine to publish (e.g. "exclude all of 10/8" in a LogsQL filter)
allowed_ipv4='^(10\.0\.0\.0|192\.168\.0\.0|172\.16\.0\.0)$'
found=0

# decrypt everything up front: a sops failure must fail the check, not silently scan nothing
values=""
for env in ../komodo-secrets/envs/*.env; do
  plain=$(sops -d "$env") || { echo "cannot decrypt $env" >&2; exit 2; }
  values+=$(grep -E '^(IP_|DOMAIN_|LOCAL_V)' <<<"$plain" | cut -d= -f2- || true)$'\n'
done
values=$(sort -u <<<"$values" | grep -v '^$' || true)
[ -n "$values" ] || { echo "no secret values read; refusing to report clean" >&2; exit 2; }

while IFS= read -r value; do
  if grep -rliF -- "$value" "$target"; then found=1; fi
done <<<"$values"

# private IPv4 literals not in the allow list
if grep -rHoE '\b(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))(\.[0-9]{1,3}){2,3}\b' "$target" \
    | awk -F: -v ok="$allowed_ipv4" '$NF !~ ok {print $1}' | sort -u | grep .; then
  found=1
fi

# IPv6 literals: global unicast (2000::/3) and ULA (fc00::/7), compressed forms included
if grep -rliE '\b([23][0-9a-f]{3}|f[cd][0-9a-f]{2}):[0-9a-f]{0,4}:' "$target"; then found=1; fi

if [ "$found" -ne 0 ]; then
  echo "private values found in the files above" >&2
  exit 1
fi
echo "no private values in $target"
