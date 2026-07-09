# gh-token-broker

A Go service that authenticates GitHub Actions OIDC callers, evaluates
operator-authored CEL policy, and mints least-privilege GitHub App
installation access tokens — either by dispatching a workflow itself (token
never leaves the process) or by returning a scoped token to the caller.

GitHub enforces a hard server-side ceiling: a token can never exceed what the
App installation was granted. This service's scoping is least-privilege
defense in depth on top of that ceiling.

## What it does

- **Caller auth: GitHub Actions OIDC only.** No API keys. Every caller
  presents a short-lived, self-verifying OIDC token.
- **Policy: CEL only.** Each rule is a CEL `when` condition plus a static
  `grant`. Rules run in order, first match wins; no match means deny.
- **Least privilege is computed, not requested.** The issued scope is the
  intersection of the matched rule's grant, the caller's requested scope, and
  the installation's actual permissions — per permission, at the minimum
  level.

## Endpoints

| Method + path                     | Purpose                                              | Registered when |
|-----------------------------------|-------------------------------------------------------|-----------------|
| `POST /actions/workflow-dispatch` | Dispatches a workflow; the token never leaves the server. | always |
| `POST /token`                     | Returns a scoped token to the caller.                  | only if `tokenIssuance.enabled` |
| `GET /healthz`                    | Liveness check, no auth.                               | always |
| `GET /openapi.json`                | OpenAPI 3.1 document for this API, no auth.            | always |

All requests carry `Authorization: Bearer <oidc-token>`. Request bodies are
size-capped; the server sets explicit read/write timeouts.

## Config shape

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

Workflow dispatch always requires `actions: write` — that's hardcoded, not
configurable, since it's exactly what GitHub's API requires and won't change.
A rule's `grant.permissions` must include `actions: write` (or `admin`) for a
dispatch through it to succeed.

### CEL policy model

- A rule's `grant` is static config, not a CEL expression — CEL only decides
  *whether* a pre-declared grant applies, never fabricates one from request
  data. First match wins, so grants are never combined across rules.
- `grant.repositories` is optional. If declared, it's a ceiling: the request's
  repositories are narrowed down to it, never expanded past it. If omitted,
  there's no additional ceiling — the requested/dispatched target passes
  through as-is, because `when` already had access to both the trusted
  `caller` identity and the requested target and is expected to have fully
  validated the relationship (e.g. `request.repositories.all(r, r ==
  caller.repository + "-gitops")`). This is what lets a rule express a pattern
  ("any repo matching this caller's own `-gitops` sibling") without
  enumerating every matching repository in config. `grant.permissions` stays
  required and static — that space is small and worth being able to audit
  without reading CEL.
- Variables exposed to CEL, and nothing else:
  - `caller` — verified, id-anchored OIDC claims: `repository`,
    `repository_id`, `repository_owner`, `repository_owner_id`,
    `job_workflow_ref` (full string, ref suffix included).
  - `caller_advisory` — `ref`, `workflow`, `actor`. Event-derived and
    fork-influenceable. **Never use these in an allow decision** — CEL can't
    enforce this, so treat any rule reading `caller_advisory` as a review
    rejection.
  - `request` — for token issuance: caller-supplied `repositories` and
    `permissions` (untrusted; narrows the grant, never defines it).
  - `action` — for workflow dispatch: `name`, `owner`, `repo`, `ref`,
    `workflow`, `inputs` (no scope fields).
- Match id-anchored claims with exact equality (`==`) or `in [...]`. No
  `contains`/`startsWith`/`matches` helpers are registered, so an unanchored
  match like `caller.repository.startsWith("acme/")` can't be written.

## Security guarantees

Each is enforced in code and covered by tests:

- **Fail closed on empty scope.** Token minting refuses to call GitHub if the
  computed repository set or permission map is empty — GitHub treats an empty
  set as "everything", so a bug producing an empty result must never reach the
  API.
- **Per-key minimum-level intersection.** `read < write < admin`; a permission
  key absent from any input is dropped, never passed through.
- **Full OIDC validation.** Issuer pinned; a required, proxy-specific
  audience checked exactly; only `RS256` accepted; JWKS fetch/cache/rotation;
  time claims validated with a configurable clock skew.
- **Dispatch always requires `actions: write`, hardcoded** — never configurable,
  never from the request body, never fetched from the target repo at request
  time. A rule's grant must cover it (checked exactly, not just "non-empty")
  for a dispatch to be authorized.
- **CEL is sandboxed.** Programs compile once at startup from config only,
  never from request data; a cost limit is enforced; oversized repository
  lists are rejected, not truncated.
- **Unknown permission keys are rejected** at config load and dropped from
  requests at runtime.
- **Every issuance and dispatch is audited** — allow and deny — with caller
  identity, matched rule, decision, and computed scope.
- **No token caching.** A fresh scoped token is minted per request.

## Running

```sh
go build ./cmd/gh-token-broker
./gh-token-broker -config config.yaml
./gh-token-broker -version
```

## Current limitations

- Token issuance is gated by a config flag (`tokenIssuance.enabled`), not a
  build tag — when disabled, `/token` is simply not registered.
- No audit-before-issue fail-closed on the token path yet, and no token
  caching.
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
