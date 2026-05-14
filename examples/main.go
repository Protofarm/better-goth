package main

import (
	"log"
	"net/http"
	"os"

	bettergoth "github.com/Protofarm/better-goth"
	"github.com/joho/godotenv"
)

const defaultConfigPath = "example.config.yaml"

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env loaded, using environment variables as-is")
	}

	configPath := defaultConfigPath
	if len(os.Args) > 1 && os.Args[1] != "" {
		configPath = os.Args[1]
	}

	mux := http.NewServeMux()
	listenAddr, err := bettergoth.StartBetterGoth(configPath, mux)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Server running on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
