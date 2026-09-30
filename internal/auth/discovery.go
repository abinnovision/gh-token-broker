package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	requestTimeout    = 10 * time.Second
	discoveryTimeout  = 15 * time.Second
	maxRedirects      = 3
	maxResponseBytes  = 1 << 20
	jwksFetchInterval = 30 * time.Second
)

// discover runs OIDC discovery for issuerURL over a dedicated client and
// returns a key set that fetches the https jwks_uri over the same client.
// base is the underlying round tripper; nil means http.DefaultTransport.
//
// Cancelling ctx after discovery does not affect the key set: go-oidc keeps
// only the client from the context it is given and ignores its cancellation.
func discover(ctx context.Context, issuerURL string, base http.RoundTripper) (oidc.KeySet, error) {
	client, tr := newClient(base)
	ctx = oidc.ClientContext(ctx, client)
	discoveryCtx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryCtx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("discovery: %.200q", err.Error())
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	u, err := url.Parse(meta.JWKSURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("discovery: jwks_uri %.200q is not an https URL", meta.JWKSURI)
	}
	tr.jwksURL = u.String()
	return oidc.NewRemoteKeySet(ctx, meta.JWKSURI), nil
}

// newClient returns an HTTP client for one issuer that follows at most
// maxRedirects redirects and sends every request through a restricting
// transport.
func newClient(base http.RoundTripper) (*http.Client, *transport) {
	if base == nil {
		base = http.DefaultTransport
	}
	tr := &transport{base: base}
	return &http.Client{
		Transport: tr,
		Timeout:   requestTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}, tr
}

// transport allows only https requests (including redirects), caps response
// bodies at maxResponseBytes and allows one request to jwksURL per
// jwksFetchInterval. A throttled fetch fails, so verification fails closed.
type transport struct {
	base    http.RoundTripper
	jwksURL string // set once after discovery, before any key fetch

	mu            sync.Mutex
	lastJWKSFetch time.Time
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-https request to %.200q", req.URL.Redacted())
	}
	if t.jwksURL != "" && req.URL.String() == t.jwksURL {
		t.mu.Lock()
		throttled := time.Since(t.lastJWKSFetch) < jwksFetchInterval
		if !throttled {
			t.lastJWKSFetch = time.Now()
		}
		t.mu.Unlock()
		if throttled {
			return nil, errors.New("JWKS fetch throttled")
		}
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, maxResponseBytes)
	return resp, nil
}
