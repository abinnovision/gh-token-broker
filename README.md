# gh-token-broker

A Go service that authenticates GitHub Actions OIDC callers, evaluates
operator-authored CEL policy, and mints least-privilege GitHub App
installation access tokens, either by dispatching a workflow itself (token
never leaves the process) or by returning a scoped token to the caller.
GitHub enforces its own hard ceiling (a token can never exceed the App
installation's grant); this service's scoping is defense in depth on top.

- **Caller auth: GitHub Actions OIDC only.**
- **Policy: CEL only.** Each rule is a CEL `when` condition plus a static
  `grant`. Rules run in order, first match wins; no match means deny.
- **Least privilege is computed, not requested.** The issued scope is the
  intersection of the matched rule's grant, the caller's requested scope, and
  the installation's actual permissions, per permission, at the minimum level.

## Endpoints

| Method + path                     | Purpose                                              | Registered when |
|-----------------------------------|-------------------------------------------------------|-----------------|
| `POST /actions/workflow-dispatch` | Dispatches a workflow; the token never leaves the server. | always |
| `POST /token`                     | Returns a scoped token to the caller.                  | only if `tokenIssuance.enabled` |
| `GET /healthz`                    | Liveness check, no auth.                               | always |
| `GET /openapi.json`                | OpenAPI 3.1 document for this API, no auth.            | always |

All requests carry `Authorization: Bearer <oidc-token>`. Request bodies are
size-capped; the server sets explicit read/write timeouts.

## Usage examples

Both examples assume a GitHub Actions job with `permissions: { id-token: write }`
that fetches its own OIDC token and sends it as a bearer token. The
`audience` query parameter must match the configured `oidc.audience`
(`gh-token-broker` in `config.example.yaml`).

### Dispatching a workflow

```yaml
jobs:
  dispatch-workflow:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Dispatch workflow
        run: |
          ID_TOKEN_RESPONSE=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=gh-token-broker")
          ID_TOKEN=$(echo "$ID_TOKEN_RESPONSE" | jq -r ".value")

          curl --header "Content-Type: application/json" \
            --request POST \
            --header "Authorization: Bearer $ID_TOKEN" \
            --data '{"owner":"acme","repo":"app","ref":"main","workflow":"deploy.yml","inputs":{}}' \
            https://<broker-host>/actions/workflow-dispatch
```

### Fetching a scoped token

Only available if `tokenIssuance.enabled: true`.

```yaml
jobs:
  fetch-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Fetch scoped token
        run: |
          ID_TOKEN_RESPONSE=$(curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=gh-token-broker")
          ID_TOKEN=$(echo "$ID_TOKEN_RESPONSE" | jq -r ".value")

          curl --header "Content-Type: application/json" \
            --request POST \
            --header "Authorization: Bearer $ID_TOKEN" \
            --data '{"repositories":["acme/app"],"permissions":{"contents":"read"}}' \
            https://<broker-host>/token
```

## Configuration

See [`config.example.yaml`](./config.example.yaml).

```yaml
oidc:
  issuer: "https://token.actions.githubusercontent.com"
  audience: "gh-token-broker"   # required, must be proxy-specific
  clockSkewSeconds: 60
githubApp:
  appId: 123456
  privateKeyPath: "/etc/gh-token-broker/app.pem"  # or privateKeyEnv: NAME
tokenIssuance:
  enabled: false                 # see "Endpoints" above
policy:
  costLimit: 10000               # CEL runtime cost limit per eval
  maxRepositories: 256           # cap on request.repositories before binding
  rules:
    - name: acme-ci-can-dispatch
      when: 'caller.repository == "acme/app"'
      grant:
        repositories: ["acme/app"]
        permissions: { actions: write, contents: read }
      onError: reject            # fail closed on eval error (default)
```

Workflow dispatch always requires `actions: write` (hardcoded, matching
GitHub's API). A rule's `grant.permissions` must include `actions: write` (or
`admin`) for a dispatch through it to succeed.

### CEL policy model

- A rule's `grant` is static config, not a CEL expression. CEL only decides
  *whether* a pre-declared grant applies, never fabricates one from request
  data. First match wins, so grants are never combined across rules.
- `grant.repositories` is an optional ceiling: if declared, the request's
  repositories are narrowed to it, never expanded. If omitted, the requested
  target passes through as-is; `when` sees both the trusted `caller` identity
  and the requested target and must fully validate the relationship (e.g.
  `request.repositories.all(r, r == caller.repository + "-gitops")`).
  `grant.permissions` is always required and static.
- Variables exposed to CEL, and nothing else:
  - `caller`: verified, id-anchored OIDC claims. `repository`,
    `repository_id`, `repository_owner`, `repository_owner_id`,
    `job_workflow_ref` (full string, ref suffix included).
  - `caller_advisory`: `ref`, `workflow`, `actor`. Event-derived and
    fork-influenceable. **Never use these in an allow decision.** CEL can't
    enforce this, so treat any rule reading `caller_advisory` as a review
    rejection.
  - `request`: for token issuance, caller-supplied `repositories` and
    `permissions` (untrusted; narrows the grant, never defines it).
  - `action`: for workflow dispatch, `name`, `owner`, `repo`, `ref`,
    `workflow`, `inputs` (no scope fields).
- Match id-anchored claims with exact equality (`==`) or `in [...]`. No
  `contains`/`startsWith`/`matches` helpers are registered, so unanchored
  matches like `caller.repository.startsWith("acme/")` can't be written.

## Security guarantees

Each is enforced in code and covered by tests:

- **Fail closed on empty scope.** Token minting refuses to call GitHub if the
  computed repository set or permission map is empty; GitHub treats an empty
  set as "everything".
- **Per-key minimum-level intersection.** `read < write < admin`; a permission
  key absent from any input is dropped, never passed through.
- **Full OIDC validation.** Issuer pinned; a required, proxy-specific
  audience checked exactly; only `RS256` accepted; JWKS fetch/cache/rotation;
  time claims validated with a configurable clock skew.
- **Dispatch always requires `actions: write`, hardcoded.** Never taken from
  config, the request body, or the target repo. A rule's grant must cover it
  exactly for a dispatch to be authorized.
- **CEL is sandboxed.** Programs compile once at startup from config only,
  never from request data; a cost limit is enforced; oversized repository
  lists are rejected, not truncated.
- **Unknown permission keys are rejected** at config load and dropped from
  requests at runtime.
- **Every issuance and dispatch is audited**, allow and deny, with caller
  identity, matched rule, decision, and computed scope.
- **No token caching.** A fresh scoped token is minted per request.

## Running

```sh
go build ./cmd/gh-token-broker
./gh-token-broker -config config.yaml
./gh-token-broker -version
```

## Limitations

- No audit-before-issue fail-closed on the token path yet.
- GitHub Actions OIDC issuer only; no generic OIDC support.
- Rule matching is exact-match only; no glob/pattern dialect.

## Layout

```
cmd/gh-token-broker/   thin main: flags, wiring, http.Server, graceful shutdown
internal/config/        YAML config + embedded JSON-schema validation + defaults + Lint
internal/perm/          canonical permission table + min-level intersection
internal/auth/          GitHub Actions OIDC verification
internal/policy/        CEL env + engine (compiled once, first-match-wins, deny-by-default)
internal/githubapp/     App JWT, installation discovery, scoped token minting
internal/actions/       built-in workflow-dispatch action
internal/audit/         structured audit events via slog
internal/server/        HTTP handlers
schema.go               //go:embed config.schema.json
```
