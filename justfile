default:
  @just --list

# ================================
# Compose Commands For local testing
# ================================
DEFAULT_COMPOSE := docker/compose.yaml
ENV_FILE := ../komodo-secrets/envs/$(HOSTNAME).env

up compose_file=DEFAULT_COMPOSE:
  test -f {{compose_file}}
  sops env-exec {{ENV_FILE}} \
    "docker compose -f {{compose_file}} up -d"

down compose_file=DEFAULT_COMPOSE:
  test -f {{compose_file}}
  sops env-exec {{ENV_FILE}} \
    "docker compose -f {{compose_file}} down"

pull compose_file=DEFAULT_COMPOSE:
  test -f {{compose_file}}
  sops env-exec {{ENV_FILE}} \
    "docker compose -f {{compose_file}} pull"

logs compose_file=DEFAULT_COMPOSE:
  sops env-exec {{ENV_FILE}} \
    "docker compose -f {{compose_file}} logs -f"

ps compose_file=DEFAULT_COMPOSE:
  sops env-exec {{ENV_FILE}} \
    "docker compose -f {{compose_file}} ps"
    
# ================================
# ================================