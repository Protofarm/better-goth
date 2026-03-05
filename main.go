package bettergoth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Auth struct {
	Providers map[string]Provider
}

type Provider interface {
	Name() string
	Config() *oauth2.Config
	Verifier() *oidc.IDTokenVerifier
}

func NewAuth() *Auth {
	return &Auth{
		Providers: map[string]Provider{},
	}
}

func (a *Auth) AddProvider(provider Provider) {
	if provider == nil {
		return
	}

	if a.Providers == nil {
		a.Providers = map[string]Provider{}
	}

	a.Providers[provider.Name()] = provider
}

func RegisterRoutes(mux *http.ServeMux, auth *Auth) {
	mux.HandleFunc("GET /api/auth/{provider}", auth.authHandler)
	mux.HandleFunc("GET /callback/{provider}", auth.callbackHandler)
}

func (a *Auth) authHandler(w http.ResponseWriter, r *http.Request) {

	providerName := r.PathValue("provider")

	provider, ok := a.Providers[providerName]
	if !ok {
		http.NotFound(w, r)
		return
	}
	state, err := generateState()
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
	})
	authURL := provider.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func generateState() (string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Auth) callbackHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")

	provider, ok := a.Providers[providerName]
	if !ok {
		http.NotFound(w, r)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}

	if state != cookie.Value {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	token, err := provider.Config().Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "failed to exchange token", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token field", http.StatusInternalServerError)
		return
	}

	idToken, err := provider.Verifier().Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify id_token", http.StatusInternalServerError)
		return
	}

	var claims map[string]interface{}

	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	println("OAuth Login Success")
	println("Access Token:", token.AccessToken)
	println("Refresh Token:", token.RefreshToken)
	println("Expiry:", token.Expiry.String())

	println("User Claims:")
	for k, v := range claims {
		fmt.Printf("%s: %v\n", k, v)
	}

	w.Write([]byte("Login successful. Check server logs."))

}
