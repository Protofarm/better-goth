package providers

// OAuthServerProviderName is the name of the built-in OAuth server provider.
const OAuthServerProviderName = "oauthserver"

// OAuthServerProvider is an OIDC provider for the built-in OAuth server.
type OAuthServerProvider struct {
	*Provider
}

// NewOAuthServerProvider creates a new OAuthServerProvider.
func NewOAuthServerProvider(issuerURL, clientID, clientSecret, redirectURL string, scopes []string) (*OAuthServerProvider, error) {
	provider, err := NewProvider(
		OAuthServerProviderName,
		issuerURL,
		clientID,
		clientSecret,
		redirectURL,
		scopes,
	)
	if err != nil {
		return nil, err
	}

	return &OAuthServerProvider{Provider: provider}, nil
}
