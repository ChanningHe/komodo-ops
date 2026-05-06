# komodo-ops

Komodo GitOps repository: centralized definitions for multi-host Docker stacks and Komodo resources.

Powered by [Komodo](https://github.com/moghtech/komodo).

## Hosts

Stacks and resource syncs are managed for the following hosts:

- kiwiserver
- nixos-rl
- poecilia
- pseudomugil

## Layout

```
komodo/resources/   Komodo resource definitions (toml), split per host as src-<host>.toml
stacks/<host>/      Per-host docker compose files and stack configuration
.githooks/          Pre-commit hooks (secret leak detection)
.github/workflows/  CI
```

## Variables and secrets

Runtime variables are encrypted with [sops](https://github.com/getsops/sops) and live in a
separate private repository (`komodo-secrets`). Komodo pulls that repo via a `BatchCloneRepo`
procedure and injects the env file path through the `SECRET_ENV_PATH` variable. No plaintext
secrets should ever be committed to this repository.

## Pre-commit hook

`.githooks/check_secrets.py` scans the staged diff before each commit and blocks anything
matching:

- Known secret prefixes (OpenAI, Anthropic, GitHub, AWS, Stripe, ...)
- High-entropy strings in config files
- Semantic secret names (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY`, ...)
- Private patterns from `.githooks/secrets-patterns` (gitignored, local-only)

Enable once per clone:

```sh
git config core.hooksPath .githooks
```

## TODO

- [x] Pin all image tags (remove `latest` and other floating tags)
- [x] Adopt [Renovate](https://docs.renovatebot.com/) for automated dependency and image updates

## License

[MIT](LICENSE)
