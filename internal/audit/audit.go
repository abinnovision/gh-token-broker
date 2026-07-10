// Package audit emits structured audit events for every token issuance and
// every action execution, both allow and deny, as JSON via slog.
package audit

import "log/slog"

// Decision is the allow/deny outcome recorded in an audit event.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Event is one audit record. Only id-anchored caller claims are recorded;
// advisory claims and (obviously) any secret material are never logged.
type Event struct {
	// Operation is "token" or "workflow-dispatch".
	Operation string
	Decision  Decision
	// Caller carries the id-anchored OIDC claims (repository, repository_owner,
	// job_workflow_ref, ...).
	Caller map[string]string
	// MatchedPolicies names every policy that contributed to the decision.
	MatchedPolicies []string
	// SkippedPolicies names policies whose CEL evaluation failed at runtime.
	SkippedPolicies []string
	// RequestedScope and ComputedScope describe the requested vs. finally
	// granted scope. Values are human-readable summaries, never tokens.
	RequestedScope map[string]any
	ComputedScope  map[string]any
	// TokenIssued is meaningful for token issuance: whether a token was returned.
	TokenIssued bool
	// Reason optionally explains a deny.
	Reason string
}

// Logger writes audit events through an slog.Logger.
type Logger struct {
	l *slog.Logger
}

// New returns an audit Logger wrapping l.
func New(l *slog.Logger) *Logger { return &Logger{l: l} }

// Log emits ev as a single structured "audit" log line.
func (a *Logger) Log(ev Event) {
	attrs := []any{
		"operation", ev.Operation,
		"decision", string(ev.Decision),
		"caller", ev.Caller,
		"matched_policies", ev.MatchedPolicies,
		"skipped_policies", ev.SkippedPolicies,
		"token_issued", ev.TokenIssued,
	}
	if ev.RequestedScope != nil {
		attrs = append(attrs, "requested_scope", ev.RequestedScope)
	}
	if ev.ComputedScope != nil {
		attrs = append(attrs, "computed_scope", ev.ComputedScope)
	}
	if ev.Reason != "" {
		attrs = append(attrs, "reason", ev.Reason)
	}
	a.l.Info("audit", attrs...)
}
