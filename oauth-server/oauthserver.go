package oauthserver

import (
	"encoding/json"
	"log"
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

type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgs      []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	RevocationEndpointAuthMethods     []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethods  []string `json:"introspection_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
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
	metadataHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		metadata := authorizationServerMetadata{
			Issuer:                            cfg.IssuerURL,
			AuthorizationEndpoint:             cfg.IssuerURL + "/authorize",
			TokenEndpoint:                     cfg.IssuerURL + "/oauth/token",
			UserinfoEndpoint:                  cfg.IssuerURL + "/userinfo",
			RevocationEndpoint:                cfg.IssuerURL + "/oauth/token/revocation",
			IntrospectionEndpoint:             cfg.IssuerURL + "/oauth/token/introspection",
			JWKSURI:                           cfg.IssuerURL + "/.well-known/jwks.json",
			ScopesSupported:                   []string{"openid", "profile", "email"},
			ResponseTypesSupported:            []string{"code"},
			GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
			TokenEndpointAuthSigningAlgs:      []string{"RS256"},
			RevocationEndpointAuthMethods:     []string{"client_secret_basic", "client_secret_post"},
			IntrospectionEndpointAuthMethods:  []string{"client_secret_basic", "client_secret_post"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			SubjectTypesSupported:             []string{"public"},
			IDTokenSigningAlgValuesSupported:  []string{"RS256"},
			ClaimsSupported:                   []string{"sub", "name", "given_name", "email", "email_verified", "picture", "iss", "aud", "iat", "exp", "auth_time", "azp", "at_hash", "nonce"},
			RequestParameterSupported:         false,
			RequestURIParameterSupported:      false,
		}

		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			log.Printf("failed to write openid configuration response: %v", err)
		}
	}
	// OpenID Connect and RFC 8414 discovery documents.
	mux.HandleFunc("/.well-known/openid-configuration", metadataHandler)
	mux.HandleFunc("/.well-known/oauth-authorization-server", metadataHandler)

	return mux, nil
}
