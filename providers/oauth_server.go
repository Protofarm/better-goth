package providers

const OAuthServerProviderName = "oauthserver"

type OAuthServerProvider struct {
	*Provider
}

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
