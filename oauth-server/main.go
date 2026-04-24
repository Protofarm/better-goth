package main

import (
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
	mux.HandleFunc("/token", handlers.TokenHandler(s, privateKey))
	mux.Handle("/userinfo", requireAuth(handlers.UserInfoHandler(s)))
	mux.HandleFunc("/.well-known/jwks.json", handlers.JWKSHandler(publicKey))
	// OpenID Connect discovery document
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
  "issuer":                                "http://localhost:8080",
  "authorization_endpoint":               "http://localhost:8080/authorize",
  "token_endpoint":                       "http://localhost:8080/token",
  "userinfo_endpoint":                    "http://localhost:8080/userinfo",
  "jwks_uri":                             "http://localhost:8080/.well-known/jwks.json",
  "scopes_supported":                     ["openid","profile","email"],
  "response_types_supported":             ["code"],
  "grant_types_supported":                ["authorization_code","refresh_token","client_credentials"],
  "token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],
  "code_challenge_methods_supported":     ["S256","plain"],
  "subject_types_supported":              ["public"],
  "id_token_signing_alg_values_supported":["RS256"]
}`))
	})

	log.Println("OAuth 2.0 server listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
