package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	bettergoth "github.com/Protofarm/better-goth"
	"github.com/Protofarm/better-goth/internal/providers"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env loaded, using environment variables as-is")
	}

	configPath := defaultConfigPath()
	if len(os.Args) > 1 && os.Args[1] != "" {
		configPath = os.Args[1]
	}

	mux := http.NewServeMux()
	runtime, err := bettergoth.Setup(configPath)
	if err != nil {
		log.Fatal(err)
	}

	runtime.Auth.SetAuthResultHandler(runtime.SessionAuthResultHandler("/dashboard"))

	// The OAuth server is now API-only (no HTML). Override the oauthserver provider's
	// authorization URL so the example app serves its own sign-in/sign-up form locally,
	// which then POSTs credentials directly to the OAuth server's /authorize endpoint.
	if p, ok := runtime.Auth.Providers[providers.OAuthServerProviderName]; ok {
		p.Config().Endpoint.AuthURL = "http://localhost" + runtime.ListenAddr + "/authorize"
	}

	if err := registerExampleRoutes(mux, runtime); err != nil {
		log.Fatal(err)
	}

	log.Printf("Server running on %s", runtime.ListenAddr)
	log.Fatal(http.ListenAndServe(runtime.ListenAddr, mux))
}

func defaultConfigPath() string {
	candidates := []string{
		"config.yaml",
		filepath.Join("examples", "config.yaml"),
	}
	for _, c := range candidates {
		if hasExampleAssets(c) {
			return c
		}
	}
	return candidates[0]
}

func hasExampleAssets(configPath string) bool {
	if _, err := os.Stat(configPath); err != nil {
		return false
	}
	tmplDir := filepath.Join(filepath.Dir(configPath), "templates")
	if _, err := os.Stat(filepath.Join(tmplDir, "home.html")); err != nil {
		return false
	}
	return true
}
