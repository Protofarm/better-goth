package oauthserver

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/Protofarm/better-goth/oauth-server/handlers"
	"github.com/Protofarm/better-goth/oauth-server/keys"
	"github.com/Protofarm/better-goth/oauth-server/middleware"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

type ServerConfig struct {
	Port         string
	IssuerURL    string
	KeyDir       string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	AuthHTMLPath string
	DevMode      bool
}

func CreateOAuthServer(cfg ServerConfig) (*http.ServeMux, error) {
	privateKM := keys.NewKeyManager(cfg.KeyDir)

	s := store.NewStore(store.Config{
		DefaultClientID:     cfg.ClientID,
		DefaultClientSecret: cfg.ClientSecret,
		DefaultRedirectURIs: cfg.RedirectURIs,
		DevMode:             cfg.DevMode,
	})
	requireAuth := middleware.RequireAuth(s, privateKM)
	mux := http.NewServeMux()
	authTemplatePath := strings.TrimSpace(cfg.AuthHTMLPath)
	if authTemplatePath == "" {
		authTemplatePath = filepath.Join(".", "templates", "auth.html")
	}
	mux.HandleFunc("/authorize", handlers.AuthorizeHandler(s, cfg.DevMode, authTemplatePath))
	mux.HandleFunc("/oauth/token", handlers.TokenHandler(s, privateKM, cfg.IssuerURL))
	mux.HandleFunc("/oauth/token/revocation", handlers.RevocationHandler(s))
	mux.HandleFunc("/oauth/token/introspection", handlers.IntrospectionHandler(s, privateKM))
	mux.Handle("/userinfo", requireAuth(handlers.UserInfoHandler(s)))
	mux.HandleFunc("/.well-known/jwks.json", handlers.JWKSHandler(privateKM))
	// admin endpoints
	mux.HandleFunc("/admin/rotate", handlers.RotateHandler(privateKM))
	// OpenID Connect discovery document
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		cfg := struct {
			Issuer                         string   `json:"issuer"`
			AuthorizationEndpoint          string   `json:"authorization_endpoint"`
			TokenEndpoint                  string   `json:"token_endpoint"`
			UserinfoEndpoint               string   `json:"userinfo_endpoint"`
			TokenRevocationEndpoint        string   `json:"tokenrevocation_endpoint"`
			TokenIntrospectionEndpoint     string   `json:"tokenintrospection_endpoint"`
			RotateKeyEndpoint              string   `json:"rotatekey_endpoint"`
			JWKSURI                        string   `json:"jwks_uri"`
			ScopesSupported                []string `json:"scopes_supported"`
			ResponseTypesSupported         []string `json:"response_types_supported"`
			GrantTypesSupported            []string `json:"grant_types_supported"`
			TokenEndpointAuthMethods       []string `json:"token_endpoint_auth_methods_supported"`
			CodeChallengeMethodsSupported  []string `json:"code_challenge_methods_supported"`
			SubjectTypesSupported          []string `json:"subject_types_supported"`
			IDTokenSigningAlgValuesSupport []string `json:"id_token_signing_alg_values_supported"`
		}{
			Issuer:                         cfg.IssuerURL,
			AuthorizationEndpoint:          cfg.IssuerURL + "/authorize",
			TokenEndpoint:                  cfg.IssuerURL + "/oauth/token",
			UserinfoEndpoint:               cfg.IssuerURL + "/userinfo",
			TokenRevocationEndpoint:        cfg.IssuerURL + "/oauth/token/revocation",
			TokenIntrospectionEndpoint:     cfg.IssuerURL + "/oauth/token/introspection",
			RotateKeyEndpoint:              cfg.IssuerURL + "/admin/rotate",
			JWKSURI:                        cfg.IssuerURL + "/.well-known/jwks.json",
			ScopesSupported:                []string{"openid", "profile", "email"},
			ResponseTypesSupported:         []string{"code"},
			GrantTypesSupported:            []string{"authorization_code", "refresh_token", "client_credentials"},
			TokenEndpointAuthMethods:       []string{"client_secret_basic", "client_secret_post"},
			CodeChallengeMethodsSupported:  []string{"S256"},
			SubjectTypesSupported:          []string{"public"},
			IDTokenSigningAlgValuesSupport: []string{"RS256"},
		}

		_ = json.NewEncoder(w).Encode(cfg)
	})

	return mux, nil
}
