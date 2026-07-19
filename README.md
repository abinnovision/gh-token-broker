# gh-token-broker

An OAuth 2.0 Security Token Service (STS) that mints least-privilege GitHub App
installation tokens for GitHub Actions workflows, gated by CEL policies.
Implements [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).

## Why a token broker?

GitHub Actions workflows that need to reach beyond their own repository hit a
ceiling quickly. The default `GITHUB_TOKEN` is scoped to the current repo: it
cannot check out a shared library, push to a sibling gitops repo, or trigger a
workflow elsewhere. Worse, events it creates are silently suppressed, so PRs and
releases opened by automation like release-please never fire downstream CI.

The usual workaround is a Personal Access Token. PATs are long-lived, broadly
scoped, tied to an individual, and hard to audit. When someone leaves or a token
leaks, every pipeline that depends on it breaks or is compromised.

GitHub Apps improve on this because installation tokens are short-lived and not
bound to a person, but a single token still has access to every repository the
App is installed on. There is no built-in way to scope it to what one workflow
actually needs.

That is the gap this broker fills. A workflow presents its OIDC identity, CEL
policies decide the exact repositories and permissions to grant, and the broker
mints a token scoped to that and nothing more. Short-lived, least-privilege,
auditable.

## How it works

1. A GitHub Actions workflow sends its OIDC ID token to the broker.
2. The broker verifies the token against GitHub's OIDC provider.
3. CEL policies determine whether the caller is authorized and which permissions to grant.
4. If authorized, the broker mints a scoped GitHub App installation token and returns it.

## Configuration

Start with [`config.example.yaml`](./config.example.yaml).

```yaml
server:
  bind: ":8080"
  issuer: "https://gh-token-broker.example.com"

oidc:
  audience: "gh-token-broker"

githubApp:
  appId: 123456
  privateKeyPath: "/etc/gh-token-broker/app.pem"

policies:
  - name: acme-ci
    condition: 'caller.repository == "acme/app" && request.repositories.all(r, r == "acme/app")'
    grant:
      permissions:
        contents: read
```

Use exactly one of `githubApp.privateKeyPath` and `githubApp.privateKeyEnv`.

## Policies

Policies are additive allow rules evaluated in no guaranteed order. The broker evaluates every policy condition and merges matching grants, using the highest permission level per key (`read < write < admin`).

**Key rules:**

- Each condition must authorize all requested repositories (`request.repositories`).
- A request succeeds only when combined grants fully cover the requested scope.
- The broker mints a token scoped to exactly what was requested.
- `grant.permissions` is required and static. See [`internal/perm/catalog_gen.go`](./internal/perm/catalog_gen.go) for supported keys and levels (generated from the GitHub REST API OpenAPI spec).
- Invalid CEL expressions prevent startup. Runtime CEL errors are logged and the policy is skipped.

### CEL variables

Conditions receive two variables. Unknown fields fail compilation at startup.

**`caller`** (verified OIDC claims from the GitHub Actions ID token):

| Field | Type | Description |
| ----- | ---- | ----------- |
| `caller.repository` | `string` | Full repo name (`owner/repo`). |
| `caller.repository_id` | `string` | Numeric repository ID. |
| `caller.repository_owner` | `string` | Owner (org or user). |
| `caller.repository_owner_id` | `string` | Numeric owner ID. |
| `caller.job_workflow_ref` | `string` | Workflow ref that triggered the run. |

**`request`** (the incoming token request):

| Field | Type | Description |
| ----- | ---- | ----------- |
| `request.repositories` | `list(string)` | Target repositories for the token. |

### Examples

Token scoped to the caller's own repository:

```cel
caller.repository == "acme/app" && request.repositories.all(r, r == "acme/app")
```

Token scoped to the caller's `-gitops` sibling:

```cel
request.repositories.all(r, r == caller.repository + "-gitops")
```

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

The easiest way to call the broker from a workflow is
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

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /token` | RFC 8693 token exchange. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata discovery. |
| `GET /.well-known/openid-configuration` | Alias of the above for client compatibility. |

Full schema available at `GET /openapi.json`.
