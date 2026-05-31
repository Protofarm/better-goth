package bettergoth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Protofarm/better-goth/database"
	"github.com/Protofarm/better-goth/pb"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	minJWTSecretBytes       = 32
	oauthStateCookieName    = "oauth_state"
	oauthVerifierCookieName = "oauth_code_verifier"
	oauthNonceCookieName    = "oauth_nonce"
	authFlowCookieMaxAge    = 300
)

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
	CookieSecure      bool
	db                *database.Instance
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

func NewAuth(secret []byte, db *database.Instance) (*Auth, error) {
	if len(bytes.TrimSpace(secret)) == 0 {
		return nil, ErrMissingJWTSecret
	}

	if len(secret) < minJWTSecretBytes {
		return nil, ErrWeakJWTSecret
	}

	return &Auth{
		Providers:    map[string]Provider{},
		jwtSecret:    append([]byte(nil), secret...),
		CookieSecure: true,
		db:           db,
	}, nil
}

func (a *Auth) SetDevMode(devMode bool) {
	a.CookieSecure = !devMode
	if devMode {
		log.Println("DEV_MODE enabled - using HTTP. Do NOT use in production.")
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

func (a *Auth) LoginHandler() func(http.ResponseWriter, *http.Request) {
	return a.authHandler
}

func (a *Auth) CallbackHandler() func(http.ResponseWriter, *http.Request) {
	return a.callbackHandler
}

func RegisterRoutes(router RouteRegistrar, auth *Auth) {
	router.HandleFunc("GET /login/{provider}", auth.LoginHandler())
	router.HandleFunc("GET /callback/{provider}", auth.CallbackHandler())
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

	a.setFlowCookie(w, oauthStateCookieName, state, 0)
	a.setFlowCookie(w, oauthVerifierCookieName, codeVerifier, authFlowCookieMaxAge)
	a.setFlowCookie(w, oauthNonceCookieName, nonce, authFlowCookieMaxAge)

	authURL := provider.Config().AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.AccessTypeOffline,
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// generateCodeVerifier generates a PKCE code_verifier per RFC 7636 & OAuth 2.1
func generateCodeVerifier() (string, error) {
	b := make([]byte, 96)
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

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("failed to close token exchange response body: %v", err)
		}
	}()

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

func (a *Auth) setFlowCookie(w http.ResponseWriter, name, value string, maxAge int) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	if maxAge > 0 {
		cookie.MaxAge = maxAge
	}

	http.SetCookie(w, cookie)
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
	providerName, provider, ok := a.resolveCallbackProvider(w, r)
	if !ok {
		return
	}

	state, code, ok := parseCallbackRequest(w, r)
	if !ok {
		return
	}

	if !validateCallbackState(w, r, state) {
		return
	}

	token, ok := exchangeCallbackToken(w, r, provider, code)
	if !ok {
		return
	}

	rawIDToken, claims, subject, ok := verifyCallbackIdentity(w, r, provider, token)
	if !ok {
		return
	}

	if !validateNonceClaim(w, r, claims) {
		return
	}

	pbuser := buildUserFromClaims(claims, subject, "")
	user := a.db.GetOrCreateUser(pbuser, providerName)
	signedToken, err := a.signJWT(user.GetSub(), token.Expiry)
	if err != nil {
		http.Error(w, "failed to sign JWT", http.StatusInternalServerError)
		return
	}

	user.Jwt = signedToken
	if err := a.handleAuthenticatedUser(r.Context(), user); err != nil {
		http.Error(w, "failed to handle user", http.StatusInternalServerError)
		return
	}

	a.writeAuthResult(w, r, &AuthResult{
		Provider:     providerName,
		User:         user,
		SignedToken:  signedToken,
		OAuthToken:   token,
		IDToken:      rawIDToken,
		RawIDClaims:  claims,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
	})
}

func (a *Auth) resolveCallbackProvider(w http.ResponseWriter, r *http.Request) (string, Provider, bool) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		http.Error(w, "provider is required; use /callback/{provider}", http.StatusBadRequest)
		return "", nil, false
	}

	provider, ok := a.Providers[providerName]
	if !ok {
		http.NotFound(w, r)
		return "", nil, false
	}

	return providerName, provider, true
}

func parseCallbackRequest(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return "", "", false
	}

	return state, code, true
}

func validateCallbackState(w http.ResponseWriter, r *http.Request, state string) bool {
	cookie, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return false
	}
	if state != cookie.Value {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return false
	}

	clearCookie(w, oauthStateCookieName)
	return true
}

func exchangeCallbackToken(w http.ResponseWriter, r *http.Request, provider Provider, code string) (*oauth2.Token, bool) {
	verifierCookie, err := r.Cookie(oauthVerifierCookieName)
	if err != nil {
		http.Error(w, "code_verifier cookie missing", http.StatusBadRequest)
		return nil, false
	}

	token, err := exchangeWithPKCE(r.Context(), provider.Config(), code, verifierCookie.Value)
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return nil, false
	}

	clearCookie(w, oauthVerifierCookieName)
	return token, true
}

func verifyCallbackIdentity(w http.ResponseWriter, r *http.Request, provider Provider, token *oauth2.Token) (string, map[string]interface{}, string, bool) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token field", http.StatusInternalServerError)
		return "", nil, "", false
	}

	idToken, err := provider.Verifier().Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify id_token", http.StatusInternalServerError)
		return "", nil, "", false
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return "", nil, "", false
	}

	subject := claimString(claims, "sub")
	if subject == "" {
		http.Error(w, "missing subject claim", http.StatusInternalServerError)
		return "", nil, "", false
	}

	return rawIDToken, claims, subject, true
}

func validateNonceClaim(w http.ResponseWriter, r *http.Request, claims map[string]interface{}) bool {
	nonceCookie, err := r.Cookie(oauthNonceCookieName)
	if err != nil {
		return true
	}

	if claimString(claims, "nonce") != nonceCookie.Value {
		http.Error(w, "nonce mismatch - possible replay attack", http.StatusBadRequest)
		return false
	}

	clearCookie(w, oauthNonceCookieName)
	return true
}

func buildUserFromClaims(claims map[string]interface{}, subject, signedToken string) *pb.User {
	return &pb.User{
		Picture:       claimString(claims, "picture"),
		Iat:           claimFloat64(claims, "iat"),
		Exp:           claimFloat64(claims, "exp"),
		Iss:           claimString(claims, "iss"),
		Azp:           claimString(claims, "azp"),
		EmailVerified: claimBool(claims, "email_verified"),
		Name:          claimString(claims, "name"),
		GivenName:     claimString(claims, "given_name"),
		Aud:           claimAudience(claims),
		Sub:           subject,
		Email:         claimString(claims, "email"),
		AtHash:        claimString(claims, "at_hash"),
		Jwt:           signedToken,
	}
}

func (a *Auth) handleAuthenticatedUser(ctx context.Context, user *pb.User) error {
	if a.userHandler == nil {
		return nil
	}

	return a.userHandler.HandleUser(ctx, user)
}

func (a *Auth) writeAuthResult(w http.ResponseWriter, r *http.Request, result *AuthResult) {
	if a.authResultHandler != nil {
		if err := a.authResultHandler.HandleAuthResult(r.Context(), w, r, result); err != nil {
			http.Error(w, "failed to handle auth result", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(result.SignedToken))
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func claimString(claims map[string]interface{}, key string) string {
	value, ok := claims[key]
	if !ok {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []interface{}:
		if len(v) > 0 {
			if item, ok := v[0].(string); ok {
				return item
			}
		}
	}

	return ""
}

func claimFloat64(claims map[string]interface{}, key string) float64 {
	value, ok := claims[key]
	if !ok {
		return 0
	}

	if floatValue, ok := value.(float64); ok {
		return floatValue
	}

	return 0
}

func claimBool(claims map[string]interface{}, key string) bool {
	value, ok := claims[key]
	if !ok {
		return false
	}

	boolValue, ok := value.(bool)
	return ok && boolValue
}

func claimAudience(claims map[string]interface{}) string {
	return claimString(claims, "aud")
}
