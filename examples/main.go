package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	bettergoth "github.com/Protofarm/better-goth/better-goth"
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

	if err := registerExampleRoutes(mux, runtime); err != nil {
		log.Fatal(err)
	}

	listenAddr := runtime.ListenAddr
	log.Printf("Server running on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func defaultConfigPath() string {
	candidates := []string{
		"config.yaml",
		filepath.Join("examples", "config.yaml"),
	}

	for _, candidate := range candidates {
		if hasExampleAssets(candidate) {
			return candidate
		}
	}

	return candidates[0]
}

func hasExampleAssets(configPath string) bool {
	if _, err := os.Stat(configPath); err != nil {
		return false
	}

	templateDir := filepath.Join(filepath.Dir(configPath), "templates")
	if _, err := os.Stat(filepath.Join(templateDir, "home.html")); err != nil {
		return false
	}

	return true
}
