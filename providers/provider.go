package providers

import (
	"context"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider represents an OIDC authentication provider.
type Provider struct {
	name     string
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewProvider creates a new Provider with the given configuration.
func NewProvider(name, issuerURL, clientID, clientSecret, redirectURL string, scopes []string) (*Provider, error) {
	provider, err := oidc.NewProvider(context.Background(), issuerURL)
	if err != nil {
		return nil, err
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       withDefaultOIDCScopes(scopes),
		Endpoint:     provider.Endpoint(),
	}

	return &Provider{
		name:     name,
		config:   cfg,
		verifier: verifier,
	}, nil
}

func (p *Provider) Name() string {
	return p.name
}

func (p *Provider) Config() *oauth2.Config {
	return p.config
}

func (p *Provider) Verifier() *oidc.IDTokenVerifier {
	return p.verifier
}

func withDefaultOIDCScopes(scopes []string) []string {
	all := append([]string{}, scopes...)
	defaults := []string{"openid", "profile", "email"}

	for _, scope := range defaults {
		if !slices.Contains(all, scope) {
			all = append(all, scope)
		}
	}

	return all
}
