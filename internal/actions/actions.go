// Package actions holds the built-in actions the server can perform on a
// caller's behalf. The only action today is workflow-dispatch: the server
// performs the dispatch itself and never returns the scoped token to the
// caller.
package actions

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-github/v66/github"
)

// WorkflowDispatch is the canonical name of the built-in workflow_dispatch
// action.
const WorkflowDispatch = "workflow-dispatch"

// RequiredPermissions maps each built-in action to the GitHub permissions it
// needs to perform its call. This is hardcoded, not operator-configurable:
// GitHub's workflow_dispatch API requires exactly `actions: write` and that
// isn't something an operator should be able to change.
var RequiredPermissions = map[string]map[string]string{
	WorkflowDispatch: {"actions": "write"},
}

// Target identifies the workflow to dispatch. It carries only the action
// target — never scope fields.
type Target struct {
	Owner    string
	Repo     string
	Ref      string
	Workflow string
	Inputs   map[string]any
}

// Dispatcher performs a workflow dispatch using a caller-scoped token.
type Dispatcher interface {
	Dispatch(ctx context.Context, token string, t Target) error
}

// GitHubDispatcher dispatches via the GitHub REST API.
type GitHubDispatcher struct {
	// BaseURL overrides the GitHub API base; empty uses the public API.
	BaseURL string
}

// Dispatch triggers the workflow using a client authenticated with the minted
// scoped token. The token is used only for this call and is not retained.
func (d GitHubDispatcher) Dispatch(ctx context.Context, token string, t Target) error {
	inputs := map[string]any{}
	for k, v := range t.Inputs {
		inputs[k] = v
	}
	client := github.NewClient(&http.Client{Timeout: 30 * time.Second}).WithAuthToken(token)
	if d.BaseURL != "" {
		var err error
		client, err = client.WithEnterpriseURLs(d.BaseURL, d.BaseURL)
		if err != nil {
			return fmt.Errorf("actions: configure base url: %w", err)
		}
	}
	event := github.CreateWorkflowDispatchEventRequest{Ref: t.Ref, Inputs: inputs}
	if _, err := client.Actions.CreateWorkflowDispatchEventByFileName(ctx, t.Owner, t.Repo, t.Workflow, event); err != nil {
		return fmt.Errorf("actions: dispatch workflow: %w", err)
	}
	return nil
}
