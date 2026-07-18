# gh-token-broker

A GitHub Actions OIDC token broker for GitHub Apps. It authenticates callers
via GitHub Actions OIDC tokens, evaluates operator-authored CEL policies, and
mints least-privilege GitHub App installation tokens using RFC 8693 OAuth 2.0
Token Exchange.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /token` | RFC 8693 token exchange — returns a scoped installation token. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata. |
| `GET /.well-known/openid-configuration` | OIDC Discovery metadata (same document). |
| `GET /healthz` | Liveness probe. |
| `GET /openapi.json` | OpenAPI document. |

The `/token` endpoint authenticates callers via the `subject_token` form field
(an OIDC ID token from GitHub Actions), not the `Authorization` header.

## Configuration

Start with [`config.example.yaml`](./config.example.yaml).

```yaml
oidc:
  audience: "gh-token-broker" # required and proxy-specific
githubApp:
  appId: 123456
  privateKeyPath: "/etc/gh-token-broker/app.pem"
tokenIssuance:
  issuer: "https://gh-token-broker.example.com"
policy:
  policies:
    - name: acme-ci
      condition: 'caller.repository == "acme/app" && request.repositories.all(r, r == "acme/app")'
      grant:
        permissions: { contents: read }
```

Use exactly one of `githubApp.privateKeyPath` and `githubApp.privateKeyEnv`.

## Policies

Policies are unordered, additive allow statements. Every `condition` is
evaluated; matching permission grants use the highest level per key
(`read < write < admin`). Each condition must authorize the requested
repositories (`request.repositories`). A request is allowed only if the
combined permissions cover its request. The broker mints exactly that
requested scope.

`grant.permissions` is required and static. Runtime CEL errors are logged and
skipped; invalid CEL prevents startup.

CEL receives only these variables:

| Variable | Contents |
| --- | --- |
| `caller` | Typed verified claims: repository, IDs, owner, and workflow ref. |
| `request` | Typed repositories list. |

## Condition examples

Allow a caller to request a token only for its own repository:

```cel
caller.repository == "acme/app" && request.repositories.all(r, r == "acme/app")
```

Allow a caller to request a token only for its `-gitops` sibling repository:

```cel
request.repositories.all(r, r == caller.repository + "-gitops")
```

Unknown `caller` or `request` fields fail policy compilation at startup.

## Run

```sh
go build ./cmd/gh-token-broker
./gh-token-broker -config config.yaml
```

```sh
go test ./...
```

## GitHub Actions usage

Each job needs `permissions: { id-token: write }`. The `audience` value must
match `oidc.audience` in the broker configuration.

### Request a scoped token

`POST /token` is an RFC 8693 OAuth 2.0 Token Exchange endpoint. The easiest
way to call it from a workflow is
[`oidc-token-cli`](https://github.com/abinnovision/oidc-token-cli), which
fetches the GitHub Actions OIDC token and performs the exchange in one step.
Install it with `brew install abinnovision/tap/oidc-token`.

```yaml
jobs:
  fetch-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: |
          TOKEN=$(oidc-token \
            --issuer https://<broker-host>/ \
            --client-id gh-token-broker \
            --grant-type token-exchange \
            --subject-token-source github-actions \
            --audience gh-token-broker \
            --resource acme/app \
            --scope "contents:read")
```

`--audience` must match `oidc.audience` in the broker configuration (it's
also sent as the RFC 8693 `audience` parameter, which the broker accepts but
does not validate against `--resource`). `--client-id` is unchecked by the
broker (`token_endpoint_auth_methods_supported` is `"none"`), so any
placeholder works. `--resource` is repeatable for multiple repositories, and
they must share one owner.
