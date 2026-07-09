// Package actions holds the built-in proxy-mediated actions (A2). In M1 the
// only action is workflow_dispatch: the proxy performs the dispatch itself and
// never returns the scoped token to the caller.
package actions

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/go-github/v66/github"
)

// WorkflowDispatch is the canonical name of the built-in workflow_dispatch
// action. It is the key operators use in the config `actions` registry to
// declare the required permissions (INV-6: scope comes from config, not the
// request).
const WorkflowDispatch = "workflow-dispatch"

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
