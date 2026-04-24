package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/Protofarm/better-goth/oauth-server/handlers"
	"github.com/Protofarm/better-goth/oauth-server/keys"
	"github.com/Protofarm/better-goth/oauth-server/middleware"
	"github.com/Protofarm/better-goth/oauth-server/store"
	"github.com/joho/godotenv"
)

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func normalizePort(port string) string {
	p := strings.TrimSpace(port)
	p = strings.TrimPrefix(p, ":")
	if p == "" {
		return "8080"
	}
	return p
}

func splitCSV(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env loaded, using environment variables as-is")
	}

	port := normalizePort(envOrDefault("OAUTH_SERVER_PORT", "8080"))
	issuerURL := strings.TrimRight(envOrDefault("OAUTH_SERVER_ISSUER_URL", "http://localhost:"+port), "/")
	keyFile := envOrDefault("OAUTH_SERVER_KEY_FILE", "private.pem")
	clientID := envOrDefault("OAUTH_SERVER_CLIENT_ID", "my-client")
	clientSecret := envOrDefault("OAUTH_SERVER_CLIENT_SECRET", "my-secret")
	redirectURIs := splitCSV(envOrDefault("OAUTH_SERVER_REDIRECT_URIS", "http://localhost:3000/callback/oauthserver"))

	privateKey, err := keys.LoadOrGenerate(keyFile)
	if err != nil {
		log.Fatalf("RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	s := store.NewStore(store.Config{
		DefaultClientID:     clientID,
		DefaultClientSecret: clientSecret,
		DefaultRedirectURIs: redirectURIs,
	})
	requireAuth := middleware.RequireAuth(publicKey)
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", handlers.AuthorizeHandler(s))
	mux.HandleFunc("/oauth/token", handlers.TokenHandler(s, privateKey, issuerURL))
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
			Issuer:                         issuerURL,
			AuthorizationEndpoint:          issuerURL + "/authorize",
			TokenEndpoint:                  issuerURL + "/oauth/token",
			UserinfoEndpoint:               issuerURL + "/userinfo",
			JWKSURI:                        issuerURL + "/.well-known/jwks.json",
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

	listenAddr := ":" + port
	log.Printf("OAuth 2.0 server listening on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
