// Package audit emits structured audit events for every token issuance,
// both allow and deny, as JSON via slog.
package audit

import (
	"log/slog"
	"time"
)

// Decision is the allow/deny outcome recorded in an audit event.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// Event is one audit record. Only the verified token metadata below and the
// issuer's declared and audit-only claims are recorded; secret material is
// never logged.
type Event struct {
	// Operation is "token".
	Operation string
	Decision  Decision
	// Issuer is the configured issuer name, IssuerURL its iss value. Together
	// with Subject, TokenID (jti, omitted when empty), IssuedAt and Expiry these
	// are forensic fields and are not visible to policies.
	Issuer    string
	IssuerURL string
	Subject   string
	TokenID   string
	IssuedAt  time.Time
	Expiry    time.Time
	// Caller carries the issuer's declared claims present in the token, as
	// exposed to policies.
	Caller map[string]string
	// AuditClaims carries the issuer's audit-only claims present in the token
	// (omitted when empty). They are not visible to policies.
	AuditClaims map[string]string
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
		"issuer", ev.Issuer,
		"issuer_url", ev.IssuerURL,
		"subject", ev.Subject,
		"issued_at", ev.IssuedAt,
		"expiry", ev.Expiry,
		"caller", ev.Caller,
		"matched_policies", ev.MatchedPolicies,
		"skipped_policies", ev.SkippedPolicies,
		"token_issued", ev.TokenIssued,
	}
	if ev.TokenID != "" {
		attrs = append(attrs, "token_id", ev.TokenID)
	}
	if len(ev.AuditClaims) > 0 {
		attrs = append(attrs, "audit_claims", ev.AuditClaims)
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
