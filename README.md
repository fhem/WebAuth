# WebAuth

`WebAuth` is a FHEM module that authenticates `FHEMWEB` requests based on HTTP
headers. The repository is module-centric and consumes the shared
`fhem-devcontainer-toolkit` as its development environment base.

<!-- BEGIN GENERATED MODULE REFERENCE -->
## Module Reference

Generated from [`FHEM/98_WebAuth.pm`](/home/runner/work/WebAuth/WebAuth/FHEM/98_WebAuth.pm).

- Summary: authenticate FHEMWEB requests based on HTTP headers
- Zusammenfassung: authentifiziert FHEMWEB Anfragen anhand von HTTP Headern
- Version: 0.3.0
- Author: Sidey
- Keywords: Authentication, Authorization, Header, Reverse Proxy, Trusted Proxy, Forward Auth, SSO, OIDC, Web

### Dependencies
- a configured FHEMWEB instance referenced by attr validFor
- an upstream reverse proxy or authentication layer that injects trusted HTTP headers

### Usage

```text
define <name> WebAuth
```

Authenticate FHEMWEB requests based on HTTP headers, typically injected by a trusted reverse proxy or external authentication layer.

### Attributes

- `headerAuthPolicy`: JSON object describing nested AND/OR groups and leaf rules. Supported matchers are: `present`, `equals`, `notEquals`, `regex`, `contains`, `prefix`, `suffix`. Syntax of a group node: `{"op":"AND|OR","items":[<node>,...]}` Syntax of a leaf rule: `{"header":"Header-Name","match":"present"}` `{"header":"Header-Name","match":"equals|notEquals|regex|contains|prefix|suffix","value":"..."}` Header lookup is case-insensitive. `contains` splits the incoming header value on commas and matches whole trimmed items. Example:

```json
{
  "op": "AND",
  "items": [
    { "header": "X-Forwarded-User", "match": "present" },
    {
      "op": "OR",
      "items": [
        { "header": "X-Auth-Source", "match": "equals", "value": "oauth2-proxy" },
        { "header": "X-Forwarded-Groups", "match": "contains", "value": "admins" }
      ]
    }
  ]
}
```
- `trustedProxy`: Regexp of trusted reverse-proxy IP addresses or hostnames. The check uses the socket peer address of the TCP connection. If the regexp does not match the peer IP directly, WebAuth also tries the reverse-resolved hostname of the peer. For literal hostname patterns like `proxy.example.org` or `^proxy.example.org$`, WebAuth additionally resolves the configured hostname via DNS and compares the resulting IP addresses with the socket peer. If the peer does not match, WebAuth does not handle the request and lets another authenticator, for example `allowed` with `basicAuth`, try next. When the peer matches, WebAuth additionally makes the peer IP and a client IP derived from `Forwarded` or `X-Forwarded-For` available to `headerAuthPolicy` via synthetic internal headers. Example:

```json
{
  "op": "AND",
  "items": [
    { "header": "X-Forwarded-User", "match": "present" },
    {
      "header": "X-FHEM-Forwarded-Client-IP",
      "match": "regex",
      "value": "^(192\\.168\\.1\\.|10\\.0\\.0\\.)"
    }
  ]
}
```
- `noCheckFor`: Regexp matching paths for which no authentication is required.
- `reportAuthAttempts {1|2|3}`: If set to 1 or 3, each successful authentication attempt will generate an event. If set to 2 or 3, each unsuccessful authentication attempt will generate an event.
- `strict {1|0}`: Controls how requests without any relevant authentication headers are handled. If set to `1` (default), such requests are denied with `403 Forbidden`. If set to `0`, WebAuth returns not-responsible and allows a later authenticator, such as `allowed` with `basicAuth`, to handle the request.
- `validFor`: Comma separated list of frontend instances for which this module is active, e.g. `WEB`.
<!-- END GENERATED MODULE REFERENCE -->

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
update add https://raw.githubusercontent.com/fhem/WebAuth/main/controls_WebAuth.txt
```
<!-- END GENERATED FHEM UPDATE COMMAND -->
