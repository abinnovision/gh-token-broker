package auth

import (
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/abinnovision/gh-token-broker/internal/config"
)

// NewWithKeySets builds an Authenticator whose issuers use the given key sets,
// keyed by issuer name, instead of OIDC discovery.
func NewWithKeySets(issuers []config.OIDCIssuer, keySets map[string]oidc.KeySet, skew time.Duration) (*Authenticator, error) {
	return newAuthenticator(issuers, skew, func(iss config.OIDCIssuer) (oidc.KeySet, error) {
		ks, ok := keySets[iss.Name]
		if !ok {
			return nil, fmt.Errorf("no key set for %q", iss.Name)
		}
		return ks, nil
	})
}
