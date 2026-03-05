package main

import (
	"log"
	"net/http"
	"os"

	bettergoth "github.com/Protofarm/better-goth"
	"github.com/Protofarm/better-goth/providers"
	"github.com/joho/godotenv"
)

func main() {

	mux := http.NewServeMux()

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	clientid := os.Getenv("GOOGLE_CLIENT_ID")
	clientsecret := os.Getenv("GOOGLE_CLIENT_SECRET")

	google, err := providers.NewGoogleProvider(
		clientid,
		clientsecret,
		"http://localhost:8080/callback/google",
		[]string{},
	)

	if err != nil {
		log.Fatal(err)
	}

	auth := &bettergoth.Auth{
		Google: google,
	}

	bettergoth.RegisterRoutes(mux, auth)

	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", mux)
}
