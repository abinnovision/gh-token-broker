# gh-token-broker

A GitHub Actions OIDC token broker for GitHub Apps. It authorizes callers with
CEL policies, then mints a scoped installation token or dispatches a workflow
without returning the token.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /actions/workflow-dispatch` | Dispatch a workflow with an internal scoped token. |
| `POST /token` | Return a scoped installation token; enabled by `tokenIssuance.enabled`. |
| `GET /healthz` | Liveness probe. |
| `GET /openapi.json` | OpenAPI document. |

Authenticated endpoints require `Authorization: Bearer <oidc-token>`.

## Configuration

Start with [`config.example.yaml`](./config.example.yaml).

```yaml
oidc:
  audience: "gh-token-broker" # required and proxy-specific
githubApp:
  appId: 123456
  privateKeyPath: "/etc/gh-token-broker/app.pem"
tokenIssuance:
  enabled: false
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
repositories (`request.repositories`). Workflow dispatch adds
`request.workflow_dispatch`; its presence and fields can further constrain a
policy. A request is allowed only if the combined permissions cover its
request. The broker mints exactly that requested scope.

`grant.permissions` is required and static. Runtime CEL errors are logged and
skipped; invalid CEL prevents startup.

CEL receives only these variables:

| Variable | Contents |
| --- | --- |
| `caller` | Typed verified claims: repository, IDs, owner, and workflow ref. |
| `request` | Typed repositories and optional `workflow_dispatch` target fields. |

Workflow dispatch always requires `actions: write`.

## Condition examples

Allow a caller to request a token only for its `-gitops` sibling repository:

```cel
request.repositories.all(r, r == caller.repository + "-gitops")
```

Allow workflow dispatch only to `acme/app`. The optional-presence check makes
this a clean non-match for token requests:

```cel
request.?workflow_dispatch.hasValue() &&
caller.repository == "acme/app" &&
request.workflow_dispatch.owner == "acme" &&
request.workflow_dispatch.repo == "app"
```

Unknown `caller`, `request`, or `workflow_dispatch` fields fail policy
compilation at startup.

## Run

```sh
go build ./cmd/gh-token-broker
./gh-token-broker -config config.yaml
```

```sh
go test ./...
```

## GitHub Actions examples

Each job needs `permissions: { id-token: write }`. The `audience` value must
match `oidc.audience` in the broker configuration.

### Dispatch a workflow

```yaml
jobs:
  dispatch-workflow:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: |
          ID_TOKEN_RESPONSE=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=gh-token-broker")
          ID_TOKEN=$(echo "$ID_TOKEN_RESPONSE" | jq -r '.value')

          curl --header "Content-Type: application/json" \
            --request POST \
            --header "Authorization: Bearer $ID_TOKEN" \
            --data '{"owner":"acme","repo":"app","ref":"main","workflow":"deploy.yml","inputs":{}}' \
            https://<broker-host>/actions/workflow-dispatch
```

### Request a scoped token

`POST /token` must be enabled with `tokenIssuance.enabled: true`.

```yaml
jobs:
  fetch-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - run: |
          ID_TOKEN_RESPONSE=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=gh-token-broker")
          ID_TOKEN=$(echo "$ID_TOKEN_RESPONSE" | jq -r '.value')

          curl --header "Content-Type: application/json" \
            --request POST \
            --header "Authorization: Bearer $ID_TOKEN" \
            --data '{"repositories":["acme/app"],"permissions":{"contents":"read"}}' \
            https://<broker-host>/token
```
