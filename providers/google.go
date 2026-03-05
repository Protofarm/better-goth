package providers

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type GoogleProvider struct {
	config   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string, scopes []string) (*GoogleProvider, error) {

	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
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
		Scopes:       append(scopes, "openid", "profile", "email"),
		Endpoint:     provider.Endpoint(),
	}

	return &GoogleProvider{
		config:   cfg,
		verifier: verifier,
	}, nil
}

func (p *GoogleProvider) Name() string {
	return "google"
}

func (p *GoogleProvider) Config() *oauth2.Config {
	return p.config
}

func (p *GoogleProvider) Verifier() *oidc.IDTokenVerifier {
	return p.verifier
}
