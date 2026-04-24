package models

import (
	"encoding/json"
	"net/url"
	"time"
)

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

func ParseURL(raw string) (URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, err
	}
	return URL{*u}, nil
}

type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Password  string `json:"-"` // never serialised
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL URL    `json:"avatar_url"`
}

type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Scopes       []string
}

type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	ExpiresAt           time.Time
	CodeChallenge       string // PKCE
	CodeChallengeMethod string // "S256" or "plain"
}

type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
	UserID       string
	ClientID     string
	ExpiresAt    time.Time
}
