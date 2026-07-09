# gh-token-broker

A single Go binary that authenticates GitHub Actions OIDC callers, evaluates
operator-authored **CEL policy**, and mints **least-privilege GitHub App
installation access tokens** — either by proxying a workflow dispatch (A2) or by
returning a scoped token to the caller (A1, when explicitly enabled).

It generalizes the design of `abinnovision/github-workflow-dispatch-proxy` from
dispatch-only to scoped, multi-purpose token issuance. GitHub itself enforces a
hard server-side ceiling (a token can never exceed what the App installation was
granted); this proxy's scoping is least-privilege **defense in depth** on top of
that ceiling.

## What it does

- **Caller auth: GitHub Actions OIDC only.** There is no API-key path. Every
  caller presents a short-lived, self-verifying OIDC token.
- **Policy: CEL only.** Each rule is a CEL `when` condition plus a static,
  operator-authored `grant`. Rules are evaluated in order, **first-match-wins**;
  if none match, the request is **denied** (deny-by-default).
- **Least privilege is computed, not requested.** The issued scope is the
  intersection of the matched rule's grant, the request/action-derived ceiling,
  and the installation's actual granted permissions — per permission key at the
  **minimum** level.

## Endpoints

| Method + path                     | Purpose                                                        | Registered when |
|-----------------------------------|----------------------------------------------------------------|-----------------|
| `POST /actions/workflow-dispatch` | A2 — proxy performs a `workflow_dispatch`; token never leaves. | always          |
| `POST /token`                     | A1 — returns a raw scoped token to the caller.                 | only if `tokenIssuance.enabled` |
| `GET /healthz`                    | Liveness. No auth.                                             | always          |

All requests carry `Authorization: Bearer <oidc-token>`. Request bodies are
size-capped and the server sets explicit read/write timeouts.

## Config shape

See [`config.example.yaml`](./config.example.yaml). Key points:

```yaml
oidc:
  issuer: "https://token.actions.githubusercontent.com"
  audience: "gh-token-broker"   # REQUIRED, proxy-specific — see security note
  clockSkewSeconds: 60
githubApp:
  appId: 123456
  privateKeyPath: "/etc/gh-token-broker/app.pem"  # or privateKeyEnv: NAME
tokenIssuance:
  enabled: false                 # A1 gate (see "Milestones")
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
actions:
  workflow-dispatch:
    permissions: { actions: write }   # A2 scope comes ONLY from here
```

### CEL policy model

- **A rule's `grant` is static config data, not a CEL expression.** CEL only
  decides *whether* the operator's own pre-declared grant applies — it can never
  fabricate a novel grant from request data. First-match-wins means grants are
  never unioned across rules, so the narrowing math stays meaningful.
- **Variables exposed to CEL (and nothing else):**
  - `caller` — verified, id-anchored OIDC claims only: `repository`,
    `repository_id`, `repository_owner`, `repository_owner_id`,
    `job_workflow_ref` (full string, ref suffix included and authoritative).
  - `caller_advisory` — `ref`, `workflow`, `actor`. **Advisory only.** These are
    event-derived / fork-influenceable. **Rule authors MUST NOT use
    `caller_advisory` in an allow decision.** CEL cannot enforce this at the type
    level, so it is a **code-review checklist item**: reject any rule that reads
    `caller_advisory`.
  - `request` — A1 only: caller-supplied `repositories` and `permissions`
    (untrusted; they narrow, never define, the ceiling).
  - `action` — A2 only: `name`, `owner`, `repo`, `ref`, `workflow`, `inputs`
    (no scope fields).
- **Anchored matching is mandatory (INV-9).** Match id-anchored claims with
  exact equality (`==`) or list membership (`in [...]`). **No string helper
  functions (`contains`/`startsWith`/`matches`) are registered** — deliberately —
  so operators cannot write an unanchored match like
  `caller.repository.startsWith("acme/")` that `acme/repo-evil` would also
  satisfy.

## Security invariants

Each is enforced in code (a guard) and covered by tests:

- **INV-1 — Empty-intersection fail-closed.** `MintScopedToken` refuses (never
  calls GitHub) if the computed repository set or permission map is empty —
  GitHub treats an empty set as "everything", so an empty result from a bug
  would silently escalate to a full-installation token. Both A1 and A2 pass
  through this single chokepoint.
- **INV-2 — Per-key minimum-level intersection.** `read < write < admin`; a key
  absent from any input is dropped, never passed through; the surviving level is
  the minimum across inputs.
- **INV-5 — OIDC validation.** Issuer pinned; a required, proxy-specific `aud`
  checked exactly (GitHub's default audience is claimable by any org workflow);
  signing-algorithm allow-list (`RS256` only — `alg=none` rejected); JWKS
  fetch/cache/rotation via `go-oidc`; `exp`/`iat`/`nbf` validated with a
  configurable clock skew (default 60s).
- **INV-6 — A2 scope from trusted config only.** The `workflow-dispatch`
  action's permissions come from the `actions` registry in config — never from
  the request body and never from fetching `action.yml` at request time. A2
  request bodies carrying `permissions`/`repositories` are rejected.
- **INV-7 — CEL safety.** Programs are compiled once at startup from operator
  config only, never from request data; request data enters evaluation only as
  typed activation variables; `cel.CostLimit` is enforced; oversized
  `request.repositories` lists are **rejected, not truncated**.
- **INV-10 — Canonical permission table.** Unknown permission keys are rejected
  at config load and dropped from A1 requests at runtime (fail closed). The
  starter table lives in `internal/perm` and is extensible.
- **INV-12 — Audit logging.** Every A1 issuance and A2 execution — allow AND
  deny — emits a structured `audit` event (id-anchored caller claims, matched
  rule, decision, computed scope, whether a token was issued).

**INV-11 — No token caching in M1.** A fresh scoped token is minted per request
(see the comment on `MintScopedToken`).

## Running

```sh
go build ./cmd/gh-token-broker
./gh-token-broker -config config.yaml
./gh-token-broker -version
```

## How M1 differs from later milestones

This is the **M1** implementation (core safe path). Deliberately deferred, per
the approved plan at `.omc/plans/gh-token-broker.md`:

- **A1 is gated by a config flag (`tokenIssuance.enabled`), not a build tag.**
  When disabled, the `/token` route is not even registered on the mux (absent,
  not 403). A future milestone may promote this to a **build-tag** so the default
  binary is *physically incapable* of exporting raw tokens.
- **No runtime audit-before-issue fail-closed for A1** (INV-12's stronger form)
  and **no token caching** (INV-11) — both are later-milestone work.
- **GitHub Actions issuer only.** Generic (non-GitHub) OIDC issuers are designed
  for but not enabled.
- **Exact-match rules only.** No glob/pattern dialect.

## Layout

```
cmd/gh-token-broker/   thin main: flags, wiring, http.Server, graceful shutdown
internal/config/        YAML config + embedded JSON-schema validation + defaults + Lint
internal/perm/          canonical permission table + min-level intersection (leaf)
internal/auth/          GitHub Actions OIDC verification
internal/policy/        CEL env + engine (compiled once, first-match-wins, deny-by-default)
internal/githubapp/     App JWT, installation discovery, scoped token minting (INV-1 chokepoint)
internal/actions/       built-in workflow_dispatch action (A2)
internal/audit/         structured audit events via slog
internal/server/        HTTP handlers
schema.go               //go:embed config.schema.json
```
