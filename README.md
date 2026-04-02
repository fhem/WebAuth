# WebAuth

`WebAuth` is a FHEM module that authenticates `FHEMWEB` requests based on HTTP
headers. The repository is module-centric and consumes the shared
`fhem-devcontainer-toolkit` as its development environment base.

## Repository Layout

- `FHEM/98_WebAuth.pm`: FHEM module
- `lib/FHEM/Core/Authentication/HeaderPolicy.pm`: shared header policy helper
- `t/`: tests
- `contrib/WebAuth/`: live example configs
- `.devcontainer/`: thin consumer layer on top of the toolkit

## Local Development

The repository does not embed a full FHEM source tree. Point `FHEM_SOURCE_ROOT`
at an external checkout, for example a sibling `fhem-mirror` clone:

```bash
cp .devcontainer/compose.local.example.yml .devcontainer/compose.local.yml
cp .devcontainer/.env.local.example .devcontainer/.env.local
```

Then set `FHEM_SOURCE_ROOT` to your external FHEM tree, e.g.
`/workspace/fhem-mirror/fhem`, and mount that checkout in
`.devcontainer/compose.local.yml`.

Perl dependencies are split into two layers:

- `.devcontainer/cpanfile`: generic toolkit/devcontainer dependencies
- `cpanfile`: WebAuth-specific dependencies used for tests and local development

## Devcontainer Profiles

- `default`: basic FHEM dev setup
- `webauth-live`: `allowed` + `WebAuth` example with a repo-local `Caddy` proxy
  and a profile-local `caddy` devcontainer feature
- `webauth-only`: strict header auth example with a repo-local `Caddy` proxy
  and a profile-local `caddy` devcontainer feature

## SVN Sync

The task `FHEM: Sync Module -> SVN` syncs only the paths listed in
`.devcontainer/svn-manifest.txt`.

## FHEM Update

The GitHub workflow generates [`controls_WebAuth.txt`](/workspace/WebAuth/controls_WebAuth.txt)
per branch. To add this branch as an update source in FHEM, use:

<!-- BEGIN GENERATED FHEM UPDATE COMMAND -->
```text
update add https://raw.githubusercontent.com/fhem/WebAuth/codex/manifest-driven-controls/controls_WebAuth.txt
```
<!-- END GENERATED FHEM UPDATE COMMAND -->
