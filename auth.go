package bettergoth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Protofarm/better-goth/pb"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const minJWTSecretBytes = 32

var (
	// ErrMissingJWTSecret is returned when the JWT secret is empty.
	ErrMissingJWTSecret = errors.New("jwt secret is required")
	// ErrWeakJWTSecret is returned when the JWT secret is less than 32 bytes.
	ErrWeakJWTSecret = errors.New("jwt secret must be at least 32 bytes")
)

// UserHandler is an interface for handling authenticated users.
type UserHandler interface {
	HandleUser(ctx context.Context, user *pb.User) error
}

// UserHandlerFunc is an adapter to allow the use of ordinary functions as UserHandlers.
type UserHandlerFunc func(context.Context, *pb.User) error

// HandleUser calls f(ctx, user).
func (f UserHandlerFunc) HandleUser(ctx context.Context, user *pb.User) error {
	return f(ctx, user)
}

// AuthResult represents the result of a successful authentication.
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

// AuthResultHandler is an interface for handling AuthResults.
type AuthResultHandler interface {
	HandleAuthResult(ctx context.Context, w http.ResponseWriter, r *http.Request, result *AuthResult) error
}

// AuthResultHandlerFunc is an adapter to allow the use of ordinary functions as AuthResultHandlers.
type AuthResultHandlerFunc func(context.Context, http.ResponseWriter, *http.Request, *AuthResult) error

// HandleAuthResult calls f(ctx, w, r, result).
func (f AuthResultHandlerFunc) HandleAuthResult(ctx context.Context, w http.ResponseWriter, r *http.Request, result *AuthResult) error {
	return f(ctx, w, r, result)
}

// Auth manages authentication providers and handlers.
type Auth struct {
	Providers         map[string]Provider
	jwtSecret         []byte
	userHandler       UserHandler
	authResultHandler AuthResultHandler
}

// SetUserHandler sets the UserHandler for Auth.
func (a *Auth) SetUserHandler(h UserHandler) {
	a.userHandler = h
}

// SetAuthResultHandler sets the AuthResultHandler for Auth.
func (a *Auth) SetAuthResultHandler(h AuthResultHandler) {
	a.authResultHandler = h
}

// Provider is an interface for authentication providers.
type Provider interface {
	Name() string
	Config() *oauth2.Config
	Verifier() *oidc.IDTokenVerifier
}

// NewAuth creates a new Auth instance with the given JWT secret.
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

// AddProvider adds an authentication provider to Auth.
func (a *Auth) AddProvider(provider Provider) {
	if provider == nil {
		return
	}

	if a.Providers == nil {
		a.Providers = map[string]Provider{}
	}

	a.Providers[provider.Name()] = provider
}

// RegisterRoutes registers the authentication routes with the given ServeMux.
func RegisterRoutes(mux *http.ServeMux, auth *Auth) {
	mux.HandleFunc("GET /login/{provider}", auth.authHandler)
	mux.HandleFunc("GET /callback/{provider}", auth.callbackHandler)
}

func (a *Auth) authHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		http.Error(w, "provider is required; use /login/{provider}", http.StatusBadRequest)
		return
	}

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

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		http.Error(w, "failed to generate code_verifier", http.StatusInternalServerError)
		return
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	nonce, err := generateState()
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Store state, verifier and nonce in secure cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_code_verifier",
		Value:    codeVerifier,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_nonce",
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	// REPLACE authURL generation:
	authURL := provider.Config().AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.AccessTypeOffline,
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// generateCodeVerifier generates a PKCE code_verifier per RFC 7636 & OAuth 2.1.
// It uses 32 bytes of randomness (256 bits of entropy).
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge creates S256 code_challenge from verifier
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// exchangeWithPKCE performs token exchange with code_verifier
func exchangeWithPKCE(ctx context.Context, cfg *oauth2.Config, code, codeVerifier string) (*oauth2.Token, error) {
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURL},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "golang/oauth2")

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, errors.New(tokenResp.Error + ": " + tokenResp.ErrorDesc)
	}

	tok := &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		RefreshToken: tokenResp.RefreshToken,
		Expiry:       time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
	}

	if tokenResp.IDToken != "" {
		tok = tok.WithExtra(map[string]interface{}{"id_token": tokenResp.IDToken})
	}

	return tok, nil
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
	if providerName == "" {
		http.Error(w, "provider is required; use /callback/{provider}", http.StatusBadRequest)
		return
	}

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

	if err := a.validateState(w, r, state); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	token, err := a.exchangeToken(r, provider, code)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Clear code_verifier cookie after successful exchange
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_code_verifier",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

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

	if err := a.validateNonce(w, r, claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

func (a *Auth) validateState(w http.ResponseWriter, r *http.Request, state string) error {
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		return errors.New("state cookie missing")
	}

	if state != cookie.Value {
		return errors.New("invalid oauth state")
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	return nil
}

func (a *Auth) exchangeToken(r *http.Request, provider Provider, code string) (*oauth2.Token, error) {
	// Retrieve code_verifier from cookie for PKCE validation
	verifierCookie, err := r.Cookie("oauth_code_verifier")
	if err != nil {
		return nil, errors.New("code_verifier cookie missing")
	}
	codeVerifier := verifierCookie.Value

	// OAuth 2.1: Exchange code with PKCE code_verifier parameter
	token, err := exchangeWithPKCE(r.Context(), provider.Config(), code, codeVerifier)
	if err != nil {
		return nil, err
	}

	// Clear code_verifier cookie after successful exchange
	// Since we don't have w here, we should probably handle it in callbackHandler
	// but for simplicity and to follow the plan of extracting logic:
	return token, nil
}

func (a *Auth) validateNonce(w http.ResponseWriter, r *http.Request, claims map[string]interface{}) error {
	nonceCookie, err := r.Cookie("oauth_nonce")
	if err != nil {
		// Nonce is optional in some flows, but if we set it, we should verify it
		return nil
	}

	claimNonce, ok := claims["nonce"].(string)
	if !ok || claimNonce != nonceCookie.Value {
		return errors.New("nonce mismatch - possible replay attack")
	}

	// Clear nonce cookie after validation
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_nonce",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	return nil
}
