# gh-token-broker

An OAuth 2.0 Security Token Service (STS) that mints least-privilege GitHub App
installation tokens for GitHub Actions workflows and other callers holding an
OIDC ID token from an issuer you configure, gated by CEL policies.
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

1. A caller, typically a GitHub Actions workflow, sends an OIDC ID token from one of the configured issuers to the broker.
2. The broker verifies the token against that issuer's signing keys and token rules.
3. CEL policies written for that issuer determine whether the caller is authorized and which permissions to grant.
4. If authorized, the broker mints a scoped GitHub App installation token and returns it.

## Configuration

Start with [`config.example.yaml`](./config.example.yaml).

```yaml
server:
  bind: ":8080"
  issuer: "https://gh-token-broker.example.com"

oidc:
  issuers:
    - name: github
      preset: github
      audience: "gh-token-broker"
      require:
        repository_owner_id: ["123456789"]

githubApp:
  appId: 123456
  privateKeyPath: "/etc/gh-token-broker/app.pem"

policies:
  - name: acme-ci
    issuer: github
    condition: 'caller.repository == "acme/app" && request.resource == "repo:acme/app"'
    grant:
      permissions:
        contents: read
```

Use exactly one of `githubApp.privateKeyPath` and `githubApp.privateKeyEnv`.

`oidc.issuers` lists every issuer whose tokens the broker accepts. Each policy
names one of them in `issuer` and is only evaluated for tokens from that issuer.

| Field | Description |
| ----- | ----------- |
| `name` | Identifier referenced by policies. Lowercase letters, digits and `-`. |
| `preset` | `github` for GitHub Actions. Supplies the issuer URL and the claims. |
| `issuer` | Canonical `https://` URL compared exactly with the token's `iss`. With `preset: github` it can only be set to `https://token.actions.githubusercontent.com/<enterprise-slug>`, for enterprises with a customized issuer. |
| `audience` | Required. The single audience every token must carry. |
| `algorithms` | Accepted signing algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `EdDSA`. Default `[RS256]`. |
| `maxTokenLifetimeSeconds` | Upper bound on `exp - iat`. Default `3600`. |
| `claims` | Token claims policies can read through `caller`. Required without a preset, not allowed with one. |
| `require` | Claim values every token must match before any policy runs, as `claim: [allowed values]`. Required without a preset. |

`oidc.clockSkewSeconds` (default `60`) applies to the `exp`, `iat` and `nbf`
checks of every issuer. The broker runs OIDC discovery for every issuer at
startup and does not start if one fails. It logs a warning for an issuer that
no policy references and for a `preset: github` issuer without `require`.

### Migration notes

Configurations with `oidc.issuer`, `oidc.audience` or policies without
`issuer` fail to load. To migrate:

1. Move `oidc.audience` into an `oidc.issuers` entry with `name: github` and
   `preset: github`. Remove `oidc.issuer`: the GitHub issuer URL can no longer
   be overridden, except with the per-enterprise form
   `https://token.actions.githubusercontent.com/<enterprise-slug>` set as
   `issuer` on the preset entry.
2. Add `issuer: github` to every policy.
3. Make every condition constrain `request.resource` with `==` or `in`.
   Comprehensions over the deprecated `request.resources` alias, such as
   `request.resources.all(r, r == "repo:acme/app")`, no longer satisfy this;
   write `request.resource == "repo:acme/app"` instead.
4. Make every condition constrain `caller` through an identity claim or a
   caller-anchored resource, unless the issuer has `require`.
   Pinning the organization with
   `require: { repository_owner_id: ["<owner id>"] }` on the GitHub entry is
   recommended either way.
5. Replace `startsWith`, `endsWith`, `contains`, `matches` and ordering
   comparisons on `caller` or `request` with `==` or `in`.

```yaml
oidc:
  issuers:
    - name: github
      preset: github
      audience: "gh-token-broker"   # previously oidc.audience
policies:
  - name: acme-ci
    issuer: github                  # new
    condition: 'caller.repository == "acme/app" && request.resource == "repo:acme/app"'
    grant:
      permissions:
        contents: read
```

See [Startup checks](#startup-checks) for the full set of condition rules.

## Request syntax

### Resources

The `resource` form field identifies what the token should grant access to. Each
value uses a typed prefix:

| Format | Description | Example |
| ------ | ----------- | ------- |
| `repo:owner/name` | A specific repository. | `repo:acme/app` |
| `org:name` | All repositories in an organization. | `org:acme` |
| `enterprise:slug` | Enterprise-level access. | `enterprise:acme-llc` |
| `owner/repo` | Shorthand for `repo:owner/repo` (backward compat). | `acme/app` |

**Constraints per request:**

- All resources must share the same **type** (no mixing `repo:` with `org:`).
- All resources must share the same **owner** (resolves to one installation).
- Only one `org:` or `enterprise:` value per request.
- Multiple `repo:` values are allowed.

For `repo:` resources the resulting token is scoped to those specific
repositories. For `org:` and `enterprise:` resources the token covers all
repositories visible to the GitHub App installation.

### Scope

The `scope` form field is a space-delimited list of `permission:level` tokens
describing the access the caller needs:

```
contents:read issues:write
```

Each permission key must exist in the
[permission catalog](./internal/perm/catalog_gen.go) (generated from the GitHub
REST API OpenAPI spec and GitHub docs permission data). Most keys support levels `read` and `write`; a few
support `admin`.

The broker grants the **intersection** of the requested scope and the GitHub App
installation's actual permissions -- it never silently downgrades, returning an
error instead if the installation does not cover the request.

## Policies

Policies are additive allow rules evaluated in no guaranteed order. The broker evaluates every policy condition once per requested resource, with `request.resource` set to that resource. For each resource it merges the grants of all policies matching that resource, using the highest permission level per key (`read < write < admin`). Grants never combine across resources.

**Key rules:**

- A policy only applies to tokens from the issuer named in its `issuer` field.
- A condition authorizes one resource at a time (`request.resource`).
- A request succeeds only when every requested resource has at least one matching policy and its combined grant fully covers the requested scope.
- Every condition must constrain `request.resource`, and `caller` through an identity claim or a caller-anchored resource unless the issuer has `require`. See [Startup checks](#startup-checks).
- The broker mints a token scoped to exactly what was requested.
- `grant.permissions` is required and static. See [`internal/perm/catalog_gen.go`](./internal/perm/catalog_gen.go) for supported keys and levels (generated from the GitHub REST API OpenAPI spec and GitHub docs permission data).
- Invalid CEL expressions and conditions that break the startup checks prevent startup. Runtime CEL errors are logged and the policy is skipped.

### CEL variables

Conditions receive two variables. Unknown fields fail compilation at startup.

**`caller`** holds the declared claims (`claims`) of the policy's issuer,
read from the verified token. Values are strings; boolean claims appear as
`"true"` or `"false"`. For the GitHub preset:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `caller.repository` | `string` | Full repo name (`owner/repo`). |
| `caller.repository_id` | `string` | Numeric repository ID. |
| `caller.repository_owner` | `string` | Owner (org or user). |
| `caller.repository_owner_id` | `string` | Numeric owner ID. |
| `caller.job_workflow_ref` | `string` | For a job using a reusable workflow, the ref path of that workflow (`owner/repo/path@ref`). |
| `caller.workflow_ref` | `string` | Ref path of the run's workflow file (`owner/repo/.github/workflows/file.yml@ref`). |
| `caller.workflow_sha` | `string` | Commit SHA of the workflow file. |
| `caller.job_workflow_sha` | `string` | For a job using a reusable workflow, the commit SHA of that workflow. |
| `caller.sha` | `string` | Commit SHA that triggered the run. |
| `caller.ref` | `string` | Git ref that triggered the run, such as `refs/heads/main`. |
| `caller.ref_type` | `string` | `branch` or `tag`. |
| `caller.ref_protected` | `string` | `"true"` when protections or rulesets are active on the ref, else `"false"`. |
| `caller.environment` | `string` | Environment used by the job. Absent when the job has none. |
| `caller.environment_node_id` | `string` | Node ID of that environment. Absent when the job has none. |
| `caller.repository_visibility` | `string` | `public`, `internal` or `private`. |
| `caller.runner_environment` | `string` | `github-hosted` or `self-hosted`. |
| `caller.enterprise` | `string` | Enterprise slug. Absent outside an enterprise. |
| `caller.enterprise_id` | `string` | Enterprise ID. Absent outside an enterprise. |
| `caller.issuer_scope` | `string` | Issuer scope as set by GitHub. Present only for some issuer configurations. |
| `caller.event_name` | `string` | Event that triggered the run, such as `push`. |
| `caller.sub` | `string` | Subject, by default `repo:owner/repo:<context>`. Organizations and repositories can customize its template. |

The identity claims `repository`, `repository_id`, `repository_owner`,
`repository_owner_id`, `workflow_ref`, `enterprise` and `enterprise_id` name
the repository, owner, workflow file or enterprise of the run, so comparing
one with a fixed value pins who the caller is. The
other claims only narrow a policy that already pins the caller, either
through an identity claim or through `require`. Any repository can have a
`refs/heads/main` branch, and `sub` does not necessarily name a repository
once its template is customized. `job_workflow_ref` names the reusable
workflow a job calls, and any repository allowed to call that workflow
produces the same value, so it is not an identity claim; use `workflow_ref`
to pin the workflow file of the calling repository.
`environment` only means something when the environment has protection rules;
without them any job can name it.

`actor`, `actor_id`, `head_ref`, `base_ref` and `workflow` are not available.
`actor` is whoever triggered the run, `head_ref` and `base_ref` are chosen by
the author of a pull request, and `workflow` is a display name any writer can
reuse.

**`request`** (the incoming token request):

| Field | Type | Description |
| ----- | ---- | ----------- |
| `request.resource` | `string` | The resource being evaluated, prefixed (e.g. `"repo:acme/app"`, `"org:acme"`). |

### Startup checks

The broker refuses to start when a condition breaks one of these rules:

- `caller` is only read as `caller.<claim>` or `caller["<claim>"]`, where
  `<claim>` is a declared claim of the policy's issuer. `has()`, optional
  access (`caller.?claim`), `"claim" in caller`, `size(caller)`, macros over
  `caller`, computed keys and bare `caller` are rejected.
- Comprehension variables may not be named `caller` or `request`.
- `startsWith`, `endsWith`, `contains` and `matches` are rejected, as are
  ordering comparisons (`<`, `<=`, `>`, `>=`) with an operand that reads
  `caller` or `request`. Use `==` or `in` instead.
- Every `||` branch compares `request.resource` with `==` or `in` against a
  value that does not read `request`. `!=`, negation and comprehensions over
  the deprecated `request.resources` alias do not count.
- Unless the issuer has `require`, every `||` branch also compares an
  identity claim (see [CEL variables](#cel-variables)) with `==` or `in`
  against a value that does not read `caller`, or compares
  `request.resource` with a caller-anchored resource, or with `in` against a
  list of them. Comparisons of other claims, such as
  `caller.ref == "refs/heads/main"`, and comparisons between two claims, such
  as `caller.repository == caller.workflow_ref`, do not count. Issuers
  without a preset have no identity claims and always have `require`.

  A caller-anchored resource is a chain of `+` over string literals and
  caller claims that starts with one of:
  - `"repo:" + caller.repository`, optionally followed by more, as in
    `"repo:" + caller.repository + "-gitops"`;
  - `"repo:" + caller.repository_owner` followed by a string literal that
    starts with `/`, as in `"repo:" + caller.repository_owner + "/tools"`;
  - `"org:" + caller.repository_owner`, with nothing after it.

  Anything else, such as a conditional, a list concatenation, a map or a
  claim in any other position, does not count as constraining the caller.
- For issuers without a preset, `request.resource` may only be compared with
  `==` against a string literal or with `in` against a list of string
  literals. Resources built from claims, such as
  `"repo:" + caller.repository`, are only allowed with the GitHub preset.

Reading a claim missing from the token is an evaluation error. The policy is
skipped for that resource and listed under `skipped_policies` in the audit
log, unless the rest of the condition decides the result without the claim.
A missing claim never makes a condition true that would be false for some
value of the claim.

### Examples

Token scoped to the caller's own repository:

```cel
caller.repository == "acme/app" && request.resource == "repo:acme/app"
```

Token scoped to the caller's `-gitops` sibling:

```cel
request.resource == "repo:" + caller.repository + "-gitops"
```

With both policies above, the caller `acme/app` can request a token for
`repo:acme/app` and `repo:acme/app-gitops` together, because each resource is
covered by its own policy.

Write access to the gitops repository, only for the deploy workflow on
`main`:

```cel
caller.workflow_ref == "acme/app/.github/workflows/deploy.yml@refs/heads/main" && request.resource == "repo:acme/app-gitops"
```

Organization-wide read access for the caller's own org:

```cel
request.resource == "org:" + caller.repository_owner
```

## Adding an issuer

Any OpenID Connect provider that serves a discovery document over https and
signs ID tokens with one of the supported algorithms can be added:

```yaml
oidc:
  issuers:
    - name: gitlab
      issuer: "https://gitlab.example.com"
      audience: "gh-token-broker"
      claims: [sub, project_path]
      require:
        namespace_id: ["4711"]

policies:
  - name: gitlab-deploy
    issuer: gitlab
    condition: 'caller.project_path == "acme/app" && request.resource == "repo:acme/app"'
    grant:
      permissions:
        contents: read
```

- **Pin the tenant in `require`.** List an immutable identifier of your
  tenant, such as a namespace, group or organization ID. Tokens the issuer
  mints for anyone else are then rejected before any policy runs. Required
  claims do not need to be listed in `claims`.
- **The audience is not an authorization check.** It prevents tokens meant for
  other services from being replayed to the broker. On many issuers any caller
  can request a token for any audience, so it says nothing about who the
  caller is.
- **Prefer `sub` and numeric or immutable IDs** over names and email
  addresses, which can be renamed, reused or reassigned.
- **Only string and boolean claims are usable.** A declared or required claim
  of another type, or a value over 1 KiB, rejects the token.
- **Tokens must** carry a non-empty `sub`, `exp` and `iat`, with `exp - iat`
  within `maxTokenLifetimeSeconds`, and exactly one audience equal to
  `audience`. `nbf` is checked when present. Tokens over 16 KiB are rejected.
- **Audit log.** Every audit event records the issuer name and URL, `sub`,
  `jti` (when present), `iat`, `exp` and the declared claims of the token.
  Declare only claims you are willing to store in logs. Of these, only the
  declared claims are visible to policies. For `preset: github` the events
  also record `run_id`, `run_number`, `run_attempt` and `check_run_id` under
  `audit_claims`. These identify the run and are not visible to policies.

The host `token.actions.githubusercontent.com` can only be used through
`preset: github`.

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
match the `audience` of the `preset: github` entry in `oidc.issuers`.

### Request a scoped token

The easiest way to call the broker from a workflow is the
[`exchange-github-token`](https://github.com/abinnovision/actions/tree/main/actions/exchange-github-token)
action. It installs [`oidc-token-cli`](https://github.com/abinnovision/oidc-token-cli),
mints the GitHub Actions OIDC token, and performs the RFC 8693 exchange in one step.

```yaml
jobs:
  fetch-token:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Exchange GitHub token
        id: token
        uses: abinnovision/actions@exchange-github-token-v1
        with:
          broker-url: https://<broker-host>/
          scope: "contents:read"
          resources: repo:acme/app # optional; defaults to the current repo
      - name: Use the token
        env:
          GH_TOKEN: ${{ steps.token.outputs.token }}
        run: gh release list
```

`resources` accepts the typed prefixes documented above (`repo:owner/name`,
`org:name`, `enterprise:slug`) and defaults to the current repository. See the
[action's README](https://github.com/abinnovision/actions/tree/main/actions/exchange-github-token)
for the full set of inputs and outputs, including the `committer-name` and
`committer-email` outputs for attributing automated commits to the App bot.

For lower-level or non-Actions use, call
[`oidc-token-cli`](https://github.com/abinnovision/oidc-token-cli) directly (the
[`setup-oidc-token-cli`](https://github.com/abinnovision/actions/tree/main/actions/setup-oidc-token-cli)
action installs it with runner caching).

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /token` | RFC 8693 token exchange. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata discovery. |
| `GET /.well-known/openid-configuration` | Alias of the above for client compatibility. |

Full schema available at `GET /openapi.json`.
