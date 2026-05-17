package bettergoth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	oauthserver "github.com/Protofarm/better-goth/oauth-server"
	"github.com/Protofarm/better-goth/pb"
	"github.com/Protofarm/better-goth/providers"
	yamlconfig "github.com/Protofarm/better-goth/yamlconfig"
)

const (
	headerContentType = "Content-Type"
	jsonContentType   = "application/json; charset=utf-8"
)

// RouteRegistrar is the minimum interface needed to register handlers.
type RouteRegistrar interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

type runtimeConfig struct {
	AppPort      string
	AppScheme    string
	DevMode      bool
	JWTSecret    string
	CookieName   string
	CookieSecure bool

	OAuthEnabled      bool
	OAuthIssuer       string
	OAuthPort         string
	OAuthClientID     string
	OAuthClientSecret string
	OAuthKeyDir       string
	OAuthRedirectURIs []string
	OAuthRedirectURL  string
	OAuthAuthHTMLPath string
	OAuthTLSCertPath  string
	OAuthTLSKeyPath   string
	OAuthTLSEnabled   bool

	GoogleEnabled      bool
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	ExternalProviders map[string]yamlconfig.ProviderConfig
}

type setupContext struct {
	configDir string
	cfg       *yamlconfig.Config
	runtime   runtimeConfig
}

// Runtime exposes the configured auth runtime so callers can register their own routes.
type Runtime struct {
	ListenAddr    string
	ConfigDir     string
	Auth          *Auth
	Store         *TokenStore
	CookieName    string
	CookieSecure  bool
	OAuthIssuer   string
	OAuthClientID string
	GoogleEnabled bool
}

// Setup wires the oauth server and providers using the YAML config.
func Setup(configPath string) (*Runtime, error) {
	ctx, err := newSetupContext(configPath)
	if err != nil {
		return nil, err
	}

	if err := ctx.startOAuthServer(); err != nil {
		return nil, err
	}

	auth, err := ctx.newAuth()
	if err != nil {
		return nil, err
	}

	if err := ctx.addProviders(auth); err != nil {
		return nil, err
	}

	return ctx.newRuntime(auth, NewTokenStore()), nil
}

func newSetupContext(configPath string) (*setupContext, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, errors.New("config path is required")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	cfg, err := yamlconfig.LoadConfig([]byte(os.ExpandEnv(string(data))))
	if err != nil {
		return nil, err
	}

	ctx := &setupContext{
		configDir: filepath.Dir(configPath),
		cfg:       cfg,
	}
	ctx.runtime = ctx.buildRuntimeConfig()
	return ctx, nil
}

func (ctx *setupContext) newRuntime(auth *Auth, store *TokenStore) *Runtime {
	rc := ctx.runtime
	return &Runtime{
		ListenAddr:    ":" + rc.AppPort,
		ConfigDir:     ctx.configDir,
		Auth:          auth,
		Store:         store,
		CookieName:    rc.CookieName,
		CookieSecure:  rc.CookieSecure,
		OAuthIssuer:   rc.OAuthIssuer,
		OAuthClientID: rc.OAuthClientID,
		GoogleEnabled: rc.GoogleEnabled,
	}
}

func (ctx *setupContext) buildRuntimeConfig() runtimeConfig {
	trim := strings.TrimSpace
	cfg := ctx.cfg

	appPort := strings.TrimPrefix(trim(cfg.App.Port), ":")
	if appPort == "" {
		appPort = "3000"
	}

	appScheme := trim(cfg.App.Scheme)
	if appScheme == "" {
		appScheme = "http"
	}

	cookieName := trim(cfg.JWT.CookieName)
	if cookieName == "" {
		cookieName = "session_id"
	}

	cookieSecure := cfg.App.CookieSecure
	if cfg.App.DevMode {
		cookieSecure = false
	}

	oauthCfg := cfg.Providers.OAuthServer

	oauthIssuer := trim(oauthCfg.IssuerURL)
	if oauthIssuer == "" {
		scheme := "https"
		if cfg.App.DevMode {
			scheme = "http"
		}
		oauthIssuer = fmt.Sprintf("%s://localhost:8080", scheme)
	}

	oauthPort := strings.TrimPrefix(trim(oauthCfg.Port), ":")
	if oauthPort == "" {
		oauthPort = "8080"
	}

	oauthClientID := trim(oauthCfg.ClientID)
	if oauthClientID == "" {
		oauthClientID = "my-client"
	}

	oauthClientSecret := trim(oauthCfg.ClientSecret)
	if oauthClientSecret == "" {
		oauthClientSecret = "my-secret"
	}

	googleCfg := cfg.Providers.Google
	rc := runtimeConfig{
		AppPort:      appPort,
		AppScheme:    appScheme,
		DevMode:      cfg.App.DevMode,
		JWTSecret:    cfg.JWT.Secret,
		CookieName:   cookieName,
		CookieSecure: cookieSecure,

		OAuthEnabled:      oauthCfg.Enabled,
		OAuthIssuer:       oauthIssuer,
		OAuthPort:         oauthPort,
		OAuthClientID:     oauthClientID,
		OAuthClientSecret: oauthClientSecret,
		OAuthKeyDir:       ctx.resolveConfigPath(oauthCfg.KeyDir, "keys"),
		OAuthAuthHTMLPath: ctx.resolveConfigPath(oauthCfg.AuthHTMLPath, filepath.Join("oauth-server", "templates", "auth.html")),
		OAuthTLSCertPath:  ctx.resolveConfigPath(oauthCfg.TLS.CertPath, ""),
		OAuthTLSKeyPath:   ctx.resolveConfigPath(oauthCfg.TLS.KeyPath, ""),
		OAuthTLSEnabled:   oauthCfg.TLS.Enabled,

		GoogleEnabled:      googleCfg.Enabled,
		GoogleClientID:     googleCfg.ClientID,
		GoogleClientSecret: googleCfg.ClientSecret,

		ExternalProviders: cfg.Providers.External,
	}

	rc.OAuthRedirectURIs = oauthCfg.RedirectURIs
	if len(rc.OAuthRedirectURIs) == 0 {
		rc.OAuthRedirectURIs = []string{
			fmt.Sprintf("%s://localhost:%s/callback/%s", rc.AppScheme, rc.AppPort, providers.OAuthServerProviderName),
		}
	}
	rc.OAuthRedirectURL = rc.OAuthRedirectURIs[0]

	rc.GoogleRedirectURI = trim(googleCfg.RedirectURI)
	if rc.GoogleRedirectURI == "" {
		rc.GoogleRedirectURI = fmt.Sprintf("%s://localhost:%s/callback/google", rc.AppScheme, rc.AppPort)
	}

	return rc
}

func (ctx *setupContext) resolveConfigPath(path, fallback string) string {
	value := strings.TrimSpace(path)
	if value == "" {
		value = fallback
	}
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(ctx.configDir, value)
}

func (ctx *setupContext) callbackURL(providerName string) string {
	rc := ctx.runtime
	return fmt.Sprintf("%s://localhost:%s/callback/%s", rc.AppScheme, rc.AppPort, providerName)
}

func (ctx *setupContext) startOAuthServer() error {
	rc := ctx.runtime
	if !rc.OAuthEnabled {
		return nil
	}

	oauthServer, err := oauthserver.CreateOAuthServer(oauthserver.ServerConfig{
		Port:         rc.OAuthPort,
		IssuerURL:    rc.OAuthIssuer,
		KeyDir:       rc.OAuthKeyDir,
		ClientID:     rc.OAuthClientID,
		ClientSecret: rc.OAuthClientSecret,
		RedirectURIs: rc.OAuthRedirectURIs,
		AuthHTMLPath: rc.OAuthAuthHTMLPath,
		DevMode:      rc.DevMode,
	})
	if err != nil {
		return err
	}

	go func() {
		listenAddr := ":" + rc.OAuthPort
		log.Printf("OAuth 2.0 server listening on %s", listenAddr)
		if rc.OAuthTLSEnabled && !rc.DevMode && rc.OAuthTLSCertPath != "" && rc.OAuthTLSKeyPath != "" {
			log.Fatal(http.ListenAndServeTLS(listenAddr, rc.OAuthTLSCertPath, rc.OAuthTLSKeyPath, oauthServer))
			return
		}
		log.Fatal(http.ListenAndServe(listenAddr, oauthServer))
	}()

	return nil
}

func (ctx *setupContext) newAuth() (*Auth, error) {
	rc := ctx.runtime
	auth, err := NewAuth([]byte(rc.JWTSecret))
	if err != nil {
		return nil, err
	}
	auth.SetDevMode(rc.DevMode)
	auth.CookieSecure = rc.CookieSecure

	auth.SetUserHandler(UserHandlerFunc(func(ctx context.Context, user *pb.User) error {
		log.Printf("authenticated user: sub=%s email=%s", user.GetSub(), user.GetEmail())
		return nil
	}))

	return auth, nil
}

func (ctx *setupContext) addProviders(auth *Auth) error {
	if err := ctx.addOAuthServerProvider(auth); err != nil {
		return err
	}

	ctx.addGoogleProvider(auth)
	ctx.addExternalProviders(auth)
	return nil
}

func (ctx *setupContext) addOAuthServerProvider(auth *Auth) error {
	rc := ctx.runtime
	if !rc.OAuthEnabled {
		return nil
	}

	oauthServerProvider, err := providers.NewOAuthServerProvider(
		rc.OAuthIssuer,
		rc.OAuthClientID,
		rc.OAuthClientSecret,
		rc.OAuthRedirectURL,
		[]string{},
	)
	if err != nil {
		return err
	}

	auth.AddProvider(oauthServerProvider)
	return nil
}

func (ctx *setupContext) addGoogleProvider(auth *Auth) {
	rc := ctx.runtime
	if !rc.GoogleEnabled {
		return
	}
	if rc.GoogleClientID == "" || rc.GoogleClientSecret == "" {
		log.Printf("Google provider enabled but missing client_id/client_secret")
		return
	}

	googleProvider, err := providers.NewGoogleProvider(
		rc.GoogleClientID,
		rc.GoogleClientSecret,
		rc.GoogleRedirectURI,
		[]string{},
	)
	if err != nil {
		log.Printf("Warning: failed to create Google provider: %v", err)
		return
	}

	auth.AddProvider(googleProvider)
	log.Printf("Google provider registered")
}

func (ctx *setupContext) addExternalProviders(auth *Auth) {
	for name, providerCfg := range ctx.runtime.ExternalProviders {
		if provider, ok := ctx.newExternalProvider(name, providerCfg); ok {
			auth.AddProvider(provider)
			log.Printf("External provider registered: %s", name)
		}
	}
}

func (ctx *setupContext) newExternalProvider(name string, providerCfg yamlconfig.ProviderConfig) (Provider, bool) {
	if !providerCfg.Enabled {
		return nil, false
	}

	issuerURL := strings.TrimSpace(providerCfg.AuthURL)
	if issuerURL == "" {
		log.Printf("External provider %q enabled but missing auth_url; expected an OIDC issuer URL", name)
		return nil, false
	}

	redirectURL := strings.TrimSpace(providerCfg.RedirectURI)
	if redirectURL == "" {
		redirectURL = ctx.callbackURL(name)
	}

	if tokenURL := strings.TrimSpace(providerCfg.TokenURL); tokenURL != "" {
		log.Printf("External provider %q token_url is ignored; provider setup uses OIDC discovery from auth_url", name)
	}

	provider, err := providers.NewProvider(
		name,
		issuerURL,
		strings.TrimSpace(providerCfg.ClientID),
		strings.TrimSpace(providerCfg.ClientSecret),
		redirectURL,
		[]string{},
	)
	if err != nil {
		log.Printf("Warning: failed to create external provider %q: %v", name, err)
		return nil, false
	}

	return provider, true
}

type TokenRecord struct {
	Provider     string `json:"provider"`
	UserSub      string `json:"user_sub"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	SignedJWT    string `json:"signed_jwt"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
}

type TokenStore struct {
	mu   sync.RWMutex
	data map[string]TokenRecord
}

func NewTokenStore() *TokenStore {
	return &TokenStore{
		data: make(map[string]TokenRecord),
	}
}

func (s *TokenStore) Save(record TokenRecord) {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[record.UserSub] = record
}

func (s *TokenStore) Get(sub string) (TokenRecord, bool) {
	if s == nil {
		return TokenRecord{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[sub]
	return v, ok
}

func (s *TokenStore) All() map[string]TokenRecord {
	if s == nil {
		return map[string]TokenRecord{}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]TokenRecord, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

type SessionAuthResultOptions struct {
	CookieName   string
	CookieSecure bool
	RedirectPath string
}

func (r *Runtime) SessionAuthResultHandler(redirectPath string) AuthResultHandler {
	return NewSessionAuthResultHandler(r.Store, SessionAuthResultOptions{
		CookieName:   r.CookieName,
		CookieSecure: r.CookieSecure,
		RedirectPath: redirectPath,
	})
}

func NewSessionAuthResultHandler(store *TokenStore, opts SessionAuthResultOptions) AuthResultHandler {
	cookieName := strings.TrimSpace(opts.CookieName)
	if cookieName == "" {
		cookieName = "session_id"
	}

	redirectPath := strings.TrimSpace(opts.RedirectPath)
	if redirectPath == "" {
		redirectPath = "/"
	}

	return AuthResultHandlerFunc(func(ctx context.Context, w http.ResponseWriter, r *http.Request, result *AuthResult) error {
		if store != nil {
			store.Save(TokenRecord{
				Provider:     result.Provider,
				UserSub:      result.User.GetSub(),
				Email:        result.User.GetEmail(),
				Name:         result.User.GetName(),
				SignedJWT:    result.SignedToken,
				AccessToken:  result.AccessToken,
				RefreshToken: result.RefreshToken,
				TokenType:    result.TokenType,
				ExpiresAt:    result.ExpiresAt.UTC().Format(time.RFC3339),
			})
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    result.SignedToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   opts.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			Expires:  result.ExpiresAt,
		})

		http.Redirect(w, r, redirectPath, http.StatusFound)
		return nil
	})
}

func AuthFromCookie(auth *Auth, cookieName, redirectPath string, next http.Handler) http.Handler {
	redirectPath = strings.TrimSpace(redirectPath)
	if redirectPath == "" {
		redirectPath = "/"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c == nil || c.Value == "" {
			http.Redirect(w, r, redirectPath, http.StatusFound)
			return
		}

		cloned := r.Clone(r.Context())
		cloned.Header.Set("Authorization", "Bearer "+c.Value)

		auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.RawQuery != "" {
				if values, parseErr := url.ParseQuery(req.URL.RawQuery); parseErr == nil {
					values.Del("code")
					values.Del("state")
					req.URL.RawQuery = values.Encode()
				}
			}
			next.ServeHTTP(w, req)
		})).ServeHTTP(w, cloned)
	})
}

func NewSessionResourceHandler(auth *Auth, cookieName, redirectPath string) http.Handler {
	return AuthFromCookie(auth, cookieName, redirectPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		WriteJSON(w, http.StatusOK, map[string]interface{}{
			"sub":            user.Subject,
			"message":        "protected resource access granted",
			"authentication": "session cookie",
		})
	}))
}

func NewBearerResourceHandler(auth *Auth) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.VerifyRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token" error_description="Authorization header must contain a valid Bearer token"`)
			WriteJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Authorization header must contain a valid Bearer token",
			})
			return
		}

		WriteJSON(w, http.StatusOK, map[string]interface{}{
			"sub":            user.Subject,
			"message":        "protected resource access granted",
			"authentication": "Bearer token",
		})
	}
}

func NewTokensListHandler(store *TokenStore) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, store.All())
	}
}

func NewTokenGetHandler(store *TokenStore) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		if sessionID == "" {
			http.Error(w, "missing sessionID path param", http.StatusBadRequest)
			return
		}

		rec, ok := store.Get(sessionID)
		if !ok {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}

		WriteJSON(w, http.StatusOK, rec)
	}
}

func NewTokenStoreHandler(store *TokenStore) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Printf("failed to close request body: %v", err)
			}
		}()

		var rec TokenRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if rec.UserSub == "" {
			http.Error(w, "missing user_sub", http.StatusBadRequest)
			return
		}

		store.Save(rec)
		WriteJSON(w, http.StatusCreated, rec)
	}
}

func NewTokenUpdateHandler(store *TokenStore) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		if sessionID == "" {
			http.Error(w, "missing sessionID path param", http.StatusBadRequest)
			return
		}

		defer func() {
			if err := r.Body.Close(); err != nil {
				log.Printf("failed to close request body: %v", err)
			}
		}()

		var rec TokenRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if rec.UserSub == "" {
			rec.UserSub = sessionID
		}
		if rec.UserSub != sessionID {
			http.Error(w, "sessionID path does not match payload user_sub", http.StatusBadRequest)
			return
		}

		store.Save(rec)
		WriteJSON(w, http.StatusOK, rec)
	}
}

func SignOutHandler(cookieName string, cookieSecure bool, redirectPath string) func(http.ResponseWriter, *http.Request) {
	redirectPath = strings.TrimSpace(redirectPath)
	if redirectPath == "" {
		redirectPath = "/"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		ClearAuthCookie(w, cookieName, cookieSecure)
		http.Redirect(w, r, redirectPath, http.StatusSeeOther)
	}
}

func ClearAuthCookie(w http.ResponseWriter, cookieName string, cookieSecure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}
func WriteJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set(headerContentType, jsonContentType)
	if status > 0 {
		w.WriteHeader(status)
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}
