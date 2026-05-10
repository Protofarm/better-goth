package models

import (
	"encoding/json"
	"net/url"
	"time"
)

// URL is a wrapper around url.URL that supports JSON marshaling.
type URL struct {
	url.URL
}

func (u URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

func (u *URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = *parsed
	return nil
}

// ParseURL parses a raw URL string into a URL struct.
func ParseURL(raw string) (URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, err
	}
	return URL{*u}, nil
}

// User represents a user in the system.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"-"` // never serialised
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL URL    `json:"avatar_url"`
}

// Client represents an OAuth 2.0 client.
type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scopes       []string
}

// AuthCode represents a temporary authorization code.
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Nonce               string
	ExpiresAt           time.Time
	CodeChallenge       string // PKCE
	CodeChallengeMethod string // "S256" or "plain"
}

// Token represents an OAuth 2.0 access and refresh token pair.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
	Nonce        string
	UserID       string
	ClientID     string
	ExpiresAt    time.Time
}
