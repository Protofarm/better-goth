package providers

// GoogleProvider is an OIDC provider for Google.
type GoogleProvider struct {
	*Provider
}

// NewGoogleProvider creates a new GoogleProvider.
func NewGoogleProvider(clientID, clientSecret, redirectURL string, scopes []string) (*GoogleProvider, error) {
	provider, err := NewProvider(
		"google",
		"https://accounts.google.com",
		clientID,
		clientSecret,
		redirectURL,
		scopes,
	)
	if err != nil {
		return nil, err
	}

	return &GoogleProvider{
		Provider: provider,
	}, nil
}
