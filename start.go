package bettergoth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
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

var ErrMissingRouter = errors.New("router is required")

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

	OAuthEnabled       bool
	OAuthIssuer        string
	OAuthPort          string
	OAuthClientID      string
	OAuthClientSecret  string
	OAuthKeyDir        string
	OAuthRedirectURIs  []string
	OAuthRedirectURL   string
	OAuthAuthHTMLPath  string
	OAuthTLSCertPath   string
	OAuthTLSKeyPath    string
	OAuthTLSEnabled    bool

	GoogleEnabled      bool
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURI  string

	GitHubEnabled bool

	TemplatesPath string
}

// StartBetterGoth wires the oauth server, providers, and example routes using the YAML config.
func StartBetterGoth(configPath string, router RouteRegistrar) (string, error) {
	if router == nil {
		return "", ErrMissingRouter
	}
	if strings.TrimSpace(configPath) == "" {
		return "", errors.New("config path is required")
	}

	cfg, err := loadConfigFromFile(configPath)
	if err != nil {
		return "", err
	}

	rc := buildRuntimeConfig(cfg, configPath)

	if err := startOAuthServer(rc); err != nil {
		return "", err
	}

	auth, store, err := setupAuth(rc)
	if err != nil {
		return "", err
	}

	if err := addProviders(auth, rc); err != nil {
		return "", err
	}

	RegisterRoutes(router, auth)

	if err := registerExampleRoutes(router, auth, store, rc); err != nil {
		return "", err
	}

	return ":" + rc.AppPort, nil
}

func buildRuntimeConfig(cfg *yamlconfig.Config, configPath string) runtimeConfig {
	configDir := filepath.Dir(configPath)
	devMode := cfg.App.DevMode
	appPort := normalizePort(cfg.App.Port)
	if appPort == "" {
		appPort = "3000"
	}
	appScheme := strings.TrimSpace(cfg.App.Scheme)
	if appScheme == "" {
		appScheme = "http"
	}
	cookieName := strings.TrimSpace(cfg.JWT.CookieName)
	if cookieName == "" {
		cookieName = "session_id"
	}
	cookieSecure := cfg.App.CookieSecure
	if devMode {
		cookieSecure = false
	}

	oauthCfg := cfg.Providers.OAuthServer
	oauthIssuer := strings.TrimSpace(oauthCfg.IssuerURL)
	if oauthIssuer == "" {
		oauthScheme := "http"
		if !devMode {
			oauthScheme = "https"
		}
		oauthIssuer = fmt.Sprintf("%s://localhost:8080", oauthScheme)
	}
	oauthPort := normalizePort(oauthCfg.Port)
	if oauthPort == "" {
		oauthPort = "8080"
	}
	oauthClientID := defaultIfEmpty(oauthCfg.ClientID, "my-client")
	oauthClientSecret := defaultIfEmpty(oauthCfg.ClientSecret, "my-secret")
	oauthKeyDir := resolvePath(configDir, defaultIfEmpty(oauthCfg.KeyDir, "keys"))
	authHTMLPath := resolvePath(configDir, oauthCfg.AuthHTMLPath)
	if authHTMLPath == "" {
		authHTMLPath = filepath.Join(configDir, "oauth-server", "templates", "auth.html")
	}
	oauthTLSCertPath := resolvePath(configDir, oauthCfg.TLS.CertPath)
	oauthTLSKeyPath := resolvePath(configDir, oauthCfg.TLS.KeyPath)

	redirectURIs := oauthCfg.RedirectURIs
	if len(redirectURIs) == 0 {
		redirectURIs = []string{
			fmt.Sprintf("%s://localhost:%s/callback/%s", appScheme, appPort, providers.OAuthServerProviderName),
		}
	}
	redirectURL := redirectURIs[0]

	googleRedirectURI := strings.TrimSpace(cfg.Providers.Google.RedirectURI)
	if googleRedirectURI == "" {
		googleRedirectURI = fmt.Sprintf("%s://localhost:%s/callback/google", appScheme, appPort)
	}

	templateDir := resolvePath(configDir, defaultIfEmpty(cfg.Templates.Path, "templates"))

	return runtimeConfig{
		AppPort:      appPort,
		AppScheme:    appScheme,
		DevMode:      devMode,
		JWTSecret:    cfg.JWT.Secret,
		CookieName:   cookieName,
		CookieSecure: cookieSecure,
		OAuthEnabled:      oauthCfg.Enabled,
		OAuthIssuer:       oauthIssuer,
		OAuthPort:         oauthPort,
		OAuthClientID:     oauthClientID,
		OAuthClientSecret: oauthClientSecret,
		OAuthKeyDir:       oauthKeyDir,
		OAuthRedirectURIs: redirectURIs,
		OAuthRedirectURL:  redirectURL,
		OAuthAuthHTMLPath: authHTMLPath,
		OAuthTLSCertPath:  oauthTLSCertPath,
		OAuthTLSKeyPath:   oauthTLSKeyPath,
		OAuthTLSEnabled:   oauthCfg.TLS.Enabled,
		GoogleEnabled:      cfg.Providers.Google.Enabled,
		GoogleClientID:     cfg.Providers.Google.ClientID,
		GoogleClientSecret: cfg.Providers.Google.ClientSecret,
		GoogleRedirectURI:  googleRedirectURI,
		GitHubEnabled: cfg.Providers.GitHub.Enabled,
		TemplatesPath: templateDir,
	}
}

func startOAuthServer(rc runtimeConfig) error {
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

func setupAuth(rc runtimeConfig) (*Auth, *tokenStore, error) {
	auth, err := NewAuth([]byte(rc.JWTSecret))
	if err != nil {
		return nil, nil, err
	}
	auth.SetDevMode(rc.DevMode)
	auth.CookieSecure = rc.CookieSecure

	store := newTokenStore()

	auth.SetUserHandler(UserHandlerFunc(func(ctx context.Context, user *pb.User) error {
		log.Printf("authenticated user: sub=%s email=%s", user.GetSub(), user.GetEmail())
		return nil
	}))

	auth.SetAuthResultHandler(AuthResultHandlerFunc(
		func(ctx context.Context, w http.ResponseWriter, r *http.Request, result *AuthResult) error {
			record := tokenRecord{
				Provider:     result.Provider,
				UserSub:      result.User.GetSub(),
				Email:        result.User.GetEmail(),
				Name:         result.User.GetName(),
				SignedJWT:    result.SignedToken,
				AccessToken:  result.AccessToken,
				RefreshToken: result.RefreshToken,
				TokenType:    result.TokenType,
				ExpiresAt:    result.ExpiresAt.UTC().Format(time.RFC3339),
			}

			go store.save(record)

			http.SetCookie(w, &http.Cookie{
				Name:     rc.CookieName,
				Value:    result.SignedToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   rc.CookieSecure,
				SameSite: http.SameSiteLaxMode,
				Expires:  result.ExpiresAt,
			})

			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return nil
		},
	))

	return auth, store, nil
}

func addProviders(auth *Auth, rc runtimeConfig) error {
	if rc.OAuthEnabled {
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
	}

	if rc.GoogleEnabled {
		if rc.GoogleClientID == "" || rc.GoogleClientSecret == "" {
			log.Printf("Google provider enabled but missing client_id/client_secret")
		} else {
			googleProvider, err := providers.NewGoogleProvider(
				rc.GoogleClientID,
				rc.GoogleClientSecret,
				rc.GoogleRedirectURI,
				[]string{},
			)
			if err != nil {
				log.Printf("Warning: failed to create Google provider: %v", err)
			} else {
				auth.AddProvider(googleProvider)
				log.Printf("Google provider registered")
			}
		}
	}

	if rc.GitHubEnabled {
		log.Printf("GitHub provider enabled but no implementation is registered")
	}

	return nil
}

func registerExampleRoutes(router RouteRegistrar, auth *Auth, store *tokenStore, rc runtimeConfig) error {
	homeTemplate, dashboardTemplate, err := loadTemplates(rc.TemplatesPath)
	if err != nil {
		return err
	}

	registerAdminRoutes(router, auth, rc)
	registerHelpRoute(router, rc)
	registerHomeRoute(router, homeTemplate, rc)
	registerDashboardRoutes(router, auth, store, dashboardTemplate, rc)
	registerResourceRoutes(router, auth, rc)
	registerTokenRoutes(router, store)
	return nil
}

func registerAdminRoutes(router RouteRegistrar, auth *Auth, rc runtimeConfig) {
	if !rc.OAuthEnabled {
		router.HandleFunc("POST /admin/rotate", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "oauth server not enabled", http.StatusServiceUnavailable)
		})
		return
	}

	router.Handle("POST /admin/rotate", authFromCookie(auth, rc.CookieName, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body, err := rotateOAuthServerKey(r.Context(), rc.OAuthIssuer)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to rotate oauth-server key: %v", err), http.StatusBadGateway)
			return
		}

		w.Header().Set(headerContentType, jsonContentType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})))
}

func registerHelpRoute(router RouteRegistrar, rc runtimeConfig) {
	router.HandleFunc("GET /help", func(w http.ResponseWriter, r *http.Request) {
		help := map[string]interface{}{
			"rdapConformance": []string{"rdapLevel0", "farv1"},
			"notices": []map[string]interface{}{
				{
					"title": "Authentication Required",
					"description": []string{
						"This RDAP server supports authentication via OpenID Connect.",
						"Use /login/oauthserver to initiate authentication.",
					},
				},
			},
			"supportedOPs": []map[string]interface{}{
				{
					"issuer":    strings.TrimRight(rc.OAuthIssuer, "/"),
					"client_id": rc.OAuthClientID,
					"scopes":    []string{"openid", "profile", "email"},
				},
			},
		}
		writeJSON(w, http.StatusOK, help)
	})
}

func registerHomeRoute(router RouteRegistrar, homeTemplate *template.Template, rc runtimeConfig) {
	providerLoginPath := "/login/" + providers.OAuthServerProviderName
	googleLoginPath := ""
	if rc.GoogleEnabled {
		googleLoginPath = "/login/google"
	}
	signupURL := strings.TrimRight(rc.OAuthIssuer, "/") + "/signup"

	router.HandleFunc("GET /{$}", handleHome(homeTemplate, providerLoginPath, googleLoginPath, signupURL))
}

func registerDashboardRoutes(router RouteRegistrar, auth *Auth, store *tokenStore, dashboardTemplate *template.Template, rc runtimeConfig) {
	router.Handle("GET /dashboard", handleDashboard(auth, store, dashboardTemplate, rc.CookieSecure, rc.CookieName))
	router.HandleFunc("POST /signout", func(w http.ResponseWriter, r *http.Request) {
		clearAuthCookie(w, rc.CookieName, rc.CookieSecure)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func registerResourceRoutes(router RouteRegistrar, auth *Auth, rc runtimeConfig) {
	router.Handle("GET /api/resource", handleAPIResource(auth, rc.CookieName))
	router.HandleFunc("GET /api/resource/bearer", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.VerifyRequest(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token" error_description="Authorization header must contain a valid Bearer token"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_token",
				"error_description": "Authorization header must contain a valid Bearer token",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sub":            user.Subject,
			"message":        "protected resource access granted",
			"authentication": "Bearer token",
		})
	})
}

func registerTokenRoutes(router RouteRegistrar, store *tokenStore) {
	registerTokensListRoute(router, store)
	registerTokenGetRoute(router, store)
	registerTokenStoreRoute(router, store)
	registerTokenUpdateRoute(router, store)
}

func registerTokensListRoute(router RouteRegistrar, store *tokenStore) {
	router.HandleFunc("GET /v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, store.all())
	})
}

func registerTokenGetRoute(router RouteRegistrar, store *tokenStore) {
	router.HandleFunc("GET /v1/tokens/{sessionID}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		if sessionID == "" {
			http.Error(w, "missing sessionID path param", http.StatusBadRequest)
			return
		}

		rec, ok := store.getBySub(sessionID)
		if !ok {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}

		writeJSON(w, http.StatusOK, rec)
	})
}

func registerTokenStoreRoute(router RouteRegistrar, store *tokenStore) {
	router.HandleFunc("POST /v1/tokens/store", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var rec tokenRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if rec.UserSub == "" {
			http.Error(w, "missing user_sub", http.StatusBadRequest)
			return
		}

		store.save(rec)

		writeJSON(w, http.StatusCreated, rec)
	})
}

func registerTokenUpdateRoute(router RouteRegistrar, store *tokenStore) {
	router.HandleFunc("PUT /v1/tokens/{sessionID}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		if sessionID == "" {
			http.Error(w, "missing sessionID path param", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		var rec tokenRecord
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

		store.save(rec)

		writeJSON(w, http.StatusOK, rec)
	})
}

type tokenRecord struct {
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

type tokenStore struct {
	mu   sync.RWMutex
	data map[string]tokenRecord
}

func newTokenStore() *tokenStore {
	return &tokenStore{
		data: make(map[string]tokenRecord),
	}
}

func (s *tokenStore) save(record tokenRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[record.UserSub] = record
}

func (s *tokenStore) getBySub(sub string) (tokenRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[sub]
	return v, ok
}

func (s *tokenStore) all() map[string]tokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]tokenRecord, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

type homeData struct {
	OAuthServerLoginPath string
	GoogleLoginPath      string
	SignupURL            string
}

func handleHome(homeTemplate *template.Template, oauthServerLoginPath, googleLoginPath, signupURL string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := homeTemplate.Execute(w, homeData{
			OAuthServerLoginPath: oauthServerLoginPath,
			GoogleLoginPath:      googleLoginPath,
			SignupURL:            signupURL,
		}); err != nil {
			http.Error(w, "failed to render home page", http.StatusInternalServerError)
			return
		}
	}
}

type routeInfo struct {
	Method      string
	Path        string
	Owner       string
	Description string
}

type dashboardData struct {
	User         *VerifiedUser
	UserDetails  *tokenRecord
	Routes       []routeInfo
	CookieSecure bool
}

func dashboardRoutes() []routeInfo {
	return []routeInfo{
		{
			Method:      "GET",
			Path:        "/help",
			Owner:       "App",
			Description: "RFC 9650 RDAP help endpoint - advertises authentication capabilities with 'farv1' support",
		},
		{
			Method:      "GET",
			Path:        "/",
			Owner:       "App",
			Description: "Homepage with login options",
		},
		{
			Method:      "GET",
			Path:        "/login/oauthserver",
			Owner:       "Library (better-goth)",
			Description: "Starts OAuth 2.0 authorization code flow against local oauth-server",
		},
		{
			Method:      "GET",
			Path:        "/callback/oauthserver",
			Owner:       "Library + App hook",
			Description: "OAuth callback - library validates, app handles result via AuthResultHandler",
		},
		{
			Method:      "GET",
			Path:        "/dashboard",
			Owner:       "App",
			Description: "Protected dashboard showing route ownership and user details (session cookie auth)",
		},
		{
			Method:      "POST",
			Path:        "/admin/rotate",
			Owner:       "App",
			Description: "Triggers oauth-server RSA key rotation through the protected app",
		},
		{
			Method:      "GET",
			Path:        "/api/resource",
			Owner:       "App",
			Description: "Protected resource endpoint using session cookie authentication (RFC 6750 via cookie)",
		},
		{
			Method:      "GET",
			Path:        "/api/resource/bearer",
			Owner:       "App",
			Description: "Protected resource endpoint using Bearer token (RFC 6750) from Authorization header",
		},
		{
			Method:      "POST",
			Path:        "/signout",
			Owner:       "App",
			Description: "Clears the JWT cookie and redirects to the homepage",
		},
		{
			Method:      "POST",
			Path:        "/v1/tokens/store",
			Owner:       "App",
			Description: "Stores a token record in the in-memory token store",
		},
		{
			Method:      "GET",
			Path:        "/v1/tokens",
			Owner:       "App",
			Description: "Returns all in-memory token records as JSON",
		},
		{
			Method:      "GET",
			Path:        "/v1/tokens/{sessionID}",
			Owner:       "App",
			Description: "Returns one in-memory token record by sessionID as JSON",
		},
		{
			Method:      "PUT",
			Path:        "/v1/tokens/{sessionID}",
			Owner:       "App",
			Description: "Updates one in-memory token record by sessionID",
		},
	}
}

func handleDashboard(auth *Auth, store *tokenStore, dashboardTemplate any, cookieSecure bool, cookieName string) http.Handler {
	return authFromCookie(auth, cookieName, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		var details *tokenRecord
		if rec, found := store.getBySub(user.Subject); found {
			details = &rec
		}

		data := dashboardData{
			User:         user,
			UserDetails:  details,
			CookieSecure: cookieSecure,
			Routes:       dashboardRoutes(),
		}

		tmpl := dashboardTemplate.(*template.Template)
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
			return
		}
	}))
}

func handleAPIResource(auth *Auth, cookieName string) http.Handler {
	return authFromCookie(auth, cookieName, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sub":            user.Subject,
			"message":        "protected resource access granted",
			"authentication": "session cookie",
		})
	}))
}

func rotateOAuthServerKey(ctx context.Context, issuerURL string) (int, []byte, error) {
	rotateURL := strings.TrimRight(issuerURL, "/") + "/admin/rotate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rotateURL, nil)
	if err != nil {
		return 0, nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, body, nil
}

func loadTemplates(templateDir string) (home *template.Template, dashboard *template.Template, err error) {
	if strings.TrimSpace(templateDir) == "" {
		templateDir = "templates"
	}

	homePath := filepath.Join(templateDir, "home.html")
	dashboardPath := filepath.Join(templateDir, "dashboard.html")

	home, err = template.ParseFiles(homePath)
	if err != nil {
		return nil, nil, err
	}

	dashboard, err = template.ParseFiles(dashboardPath)
	if err != nil {
		return nil, nil, err
	}

	return home, dashboard, nil
}

func clearAuthCookie(w http.ResponseWriter, cookieName string, cookieSecure bool) {
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

// authFromCookie adapts cookie JWT into Authorization header so existing library auth middleware can be reused.
func authFromCookie(auth *Auth, cookieName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c == nil || c.Value == "" {
			http.Redirect(w, r, "/", http.StatusFound)
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

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set(headerContentType, jsonContentType)
	if status > 0 {
		w.WriteHeader(status)
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func resolvePath(baseDir, path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}

func normalizePort(port string) string {
	p := strings.TrimSpace(port)
	p = strings.TrimPrefix(p, ":")
	return p
}

func defaultIfEmpty(value, fallback string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return fallback
	}
	return v
}

func loadConfigFromFile(configPath string) (*yamlconfig.Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	expanded := os.ExpandEnv(string(data))
	return yamlconfig.LoadConfig([]byte(expanded))
}
