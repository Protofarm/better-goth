package bettergoth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/Protofarm/better-goth/pb"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const minJWTSecretBytes = 32

var (
	ErrMissingJWTSecret = errors.New("jwt secret is required")
	ErrWeakJWTSecret    = errors.New("jwt secret must be at least 32 bytes")
)

type UserHandler interface {
	HandleUser(ctx context.Context, user *pb.User) error
}

type UserHandlerFunc func(context.Context, *pb.User) error

func (f UserHandlerFunc) HandleUser(ctx context.Context, user *pb.User) error {
	return f(ctx, user)
}

type AuthResult struct {
	Provider     string
	User         *pb.User
	SignedToken  string
	OAuthToken   *oauth2.Token
	IDToken      string
	RawIDClaims  map[string]interface{}
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
}

type AuthResultHandler interface {
	HandleAuthResult(ctx context.Context, w http.ResponseWriter, r *http.Request, result *AuthResult) error
}

type AuthResultHandlerFunc func(context.Context, http.ResponseWriter, *http.Request, *AuthResult) error

func (f AuthResultHandlerFunc) HandleAuthResult(ctx context.Context, w http.ResponseWriter, r *http.Request, result *AuthResult) error {
	return f(ctx, w, r, result)
}

type Auth struct {
	Providers         map[string]Provider
	jwtSecret         []byte
	userHandler       UserHandler
	authResultHandler AuthResultHandler
}

func (a *Auth) SetUserHandler(h UserHandler) {
	a.userHandler = h
}

func (a *Auth) SetAuthResultHandler(h AuthResultHandler) {
	a.authResultHandler = h
}

type Provider interface {
	Name() string
	Config() *oauth2.Config
	Verifier() *oidc.IDTokenVerifier
}

func NewAuth(secret []byte) (*Auth, error) {
	if len(bytes.TrimSpace(secret)) == 0 {
		return nil, ErrMissingJWTSecret
	}

	if len(secret) < minJWTSecretBytes {
		return nil, ErrWeakJWTSecret
	}

	return &Auth{
		Providers: map[string]Provider{},
		jwtSecret: append([]byte(nil), secret...),
	}, nil
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
	println("Registering auth routes")
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

func (a *Auth) signJWT(subject string, expiresAt time.Time) (string, error) {
	if len(a.jwtSecret) == 0 {
		return "", ErrMissingJWTSecret
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(expiresAt.UTC()),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
	})

	return jwtToken.SignedString(a.jwtSecret)
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

	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		http.Error(w, "missing subject claim", http.StatusInternalServerError)
		return
	}

	signedToken, err := a.signJWT(subject, token.Expiry)
	if err != nil {
		http.Error(w, "failed to sign JWT", http.StatusInternalServerError)
		return
	}

	u := &pb.User{
		Picture:       claims["picture"].(string),
		Iat:           claims["iat"].(float64),
		Exp:           claims["exp"].(float64),
		Iss:           claims["iss"].(string),
		Azp:           claims["azp"].(string),
		EmailVerified: claims["email_verified"].(bool),
		Name:          claims["name"].(string),
		GivenName:     claims["given_name"].(string),
		Aud:           claims["aud"].(string),
		Sub:           subject,
		Email:         claims["email"].(string),
		AtHash:        claims["at_hash"].(string),
		Jwt:           signedToken,
	}

	if a.userHandler != nil {
		if err := a.userHandler.HandleUser(r.Context(), u); err != nil {
			http.Error(w, "failed to handle user", http.StatusInternalServerError)
			return
		}
	}

	result := &AuthResult{
		Provider:     providerName,
		User:         u,
		SignedToken:  signedToken,
		OAuthToken:   token,
		IDToken:      rawIDToken,
		RawIDClaims:  claims,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
	}

	if a.authResultHandler != nil {
		if err := a.authResultHandler.HandleAuthResult(r.Context(), w, r, result); err != nil {
			http.Error(w, "failed to handle auth result", http.StatusInternalServerError)
			return
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(signedToken))
}
