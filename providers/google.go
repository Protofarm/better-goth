package providers

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type GoogleProvider struct {
	Config   *oauth2.Config
	Verifier *oidc.IDTokenVerifier
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string, scopes []string) (*GoogleProvider, error) {
	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	if err != nil {
		return nil, err
	}

	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       append(scopes, "openid", "profile", "email"),
		Endpoint:     provider.Endpoint(),
	}

	return &GoogleProvider{
		Config:   cfg,
		Verifier: verifier,
	}, nil
}
