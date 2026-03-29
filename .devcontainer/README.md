## Toolkit-managed devcontainer

This `.devcontainer` directory is the thin consumer layer generated from the
FHEM Devcontainer Toolkit.

By default the generated wrappers resolve the toolkit checkout from the sibling
repository `../fhem-devcontainer-toolkit`.

Local, user-specific overrides belong in:

- `.devcontainer/compose.local.yml`
- `.devcontainer/.env.local`

These files are intentionally not versioned.

The `webauth-live` and `webauth-only` profiles add a repo-local `Caddy` proxy
layer from `.devcontainer/compose.webauth-proxy.yml`. The default profile stays
on the generic toolkit core without a reverse proxy.
