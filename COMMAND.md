Command References

## Usage

### sops

deloy a stack with secrets without komodo in CLI.
```
sops env-exec ../komodo-secrets/envs/$HOSTNAME.env 'docker compose -f xxx/compose.yaml up -d'
```

### crane

check the digest, manifest and config of an image (e.g. to verify that a tag points to the expected image).
```
# List the tags in a repo
crane ls nginx:latest
# Get the digest of an image
crane digest nginx:latest
crane manifest nginx:latest
crane config nginx:latest | jq
```
