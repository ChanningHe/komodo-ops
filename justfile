default:
  @just --list

# ================================
# Compose Commands For local testing
# Run on the stack's host, e.g. `just up stacks/<host>/<stack>`.
# Secrets come from ../komodo-secrets/envs/$HOSTNAME.env; override with SECRET_ENV_PATH.
# ================================
ENV_FILE := env_var_or_default("SECRET_ENV_PATH", "../komodo-secrets/envs/" + env_var_or_default("HOSTNAME", `hostname -s`) + ".env")

up stack_dir: (_compose stack_dir "up -d")

down stack_dir: (_compose stack_dir "down")

pull stack_dir: (_compose stack_dir "pull")

logs stack_dir: (_compose stack_dir "logs -f")

ps stack_dir: (_compose stack_dir "ps")

# validate compose interpolation without printing secrets
check stack_dir: (_compose stack_dir "config --quiet")

[private]
_compose stack_dir args:
  #!/usr/bin/env bash
  set -euo pipefail
  dir="{{ trim_end_match(stack_dir, '/') }}"
  test -f "$dir/compose.yaml" || { echo "no compose.yaml in $dir" >&2; exit 1; }
  test -f "{{ ENV_FILE }}" || { echo "secret env not found: {{ ENV_FILE }}" >&2; exit 1; }
  # Komodo gets DOCKER_DATA from the periphery env; empty here would bind-mount under /
  if grep -rqs DOCKER_DATA "$dir" && [ -z "${DOCKER_DATA:-}" ]; then
    echo "DOCKER_DATA is not set in this shell" >&2; exit 1
  fi
  env_files=""
  for f in .env compose.env; do
    if [ -f "$dir/$f" ]; then env_files="$env_files --env-file $dir/$f"; fi
  done
  sops exec-env "{{ ENV_FILE }}" "docker compose -f $dir/compose.yaml $env_files {{ args }}"

# ================================
# ================================
