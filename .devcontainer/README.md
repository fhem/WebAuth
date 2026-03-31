## Toolkit-managed devcontainer

This `.devcontainer` directory is the thin consumer layer generated from the
FHEM Devcontainer Toolkit.

By default the generated wrappers resolve the toolkit checkout from the sibling
repository `../fhem-devcontainer-toolkit`.

Local, user-specific overrides belong in:

- `.devcontainer/compose.local.yml`
- `.devcontainer/.env.local`

These files are intentionally not versioned.

The scaffold uses a generic container user named `dev` by default. Override
`LOCAL_USER`, `LOCAL_UID`, and `LOCAL_GID` in local compose overrides if your
host setup needs matching ownership or different home-directory mount targets.
