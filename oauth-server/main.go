package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/Protofarm/better-goth/oauth-server/handlers"
	"github.com/Protofarm/better-goth/oauth-server/keys"
	"github.com/Protofarm/better-goth/oauth-server/middleware"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

const keyFile = "private.pem"

func main() {
	privateKey, err := keys.LoadOrGenerate(keyFile)
	if err != nil {
		log.Fatalf("RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	s := store.NewStore()
	requireAuth := middleware.RequireAuth(publicKey)
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", handlers.AuthorizeHandler(s))
	mux.HandleFunc("/oauth/token", handlers.TokenHandler(s, privateKey))
	mux.Handle("/userinfo", requireAuth(handlers.UserInfoHandler(s)))
	mux.HandleFunc("/.well-known/jwks.json", handlers.JWKSHandler(publicKey))
	// OpenID Connect discovery document
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		cfg := struct {
			Issuer                         string   `json:"issuer"`
			AuthorizationEndpoint          string   `json:"authorization_endpoint"`
			TokenEndpoint                  string   `json:"token_endpoint"`
			UserinfoEndpoint               string   `json:"userinfo_endpoint"`
			JWKSURI                        string   `json:"jwks_uri"`
			ScopesSupported                []string `json:"scopes_supported"`
			ResponseTypesSupported         []string `json:"response_types_supported"`
			GrantTypesSupported            []string `json:"grant_types_supported"`
			TokenEndpointAuthMethods       []string `json:"token_endpoint_auth_methods_supported"`
			CodeChallengeMethodsSupported  []string `json:"code_challenge_methods_supported"`
			SubjectTypesSupported          []string `json:"subject_types_supported"`
			IDTokenSigningAlgValuesSupport []string `json:"id_token_signing_alg_values_supported"`
		}{
			Issuer:                         "http://localhost:8080",
			AuthorizationEndpoint:          "http://localhost:8080/authorize",
			TokenEndpoint:                  "http://localhost:8080/oauth/token",
			UserinfoEndpoint:               "http://localhost:8080/userinfo",
			JWKSURI:                        "http://localhost:8080/.well-known/jwks.json",
			ScopesSupported:                []string{"openid", "profile", "email"},
			ResponseTypesSupported:         []string{"code"},
			GrantTypesSupported:            []string{"authorization_code", "refresh_token", "client_credentials"},
			TokenEndpointAuthMethods:       []string{"client_secret_basic", "client_secret_post"},
			CodeChallengeMethodsSupported:  []string{"S256", "plain"},
			SubjectTypesSupported:          []string{"public"},
			IDTokenSigningAlgValuesSupport: []string{"RS256"},
		}

		_ = json.NewEncoder(w).Encode(cfg)
	})

	log.Println("OAuth 2.0 server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
