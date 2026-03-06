package main

import (
	"context"
	"log"
	"net/http"
	"os"

	bettergoth "github.com/Protofarm/better-goth"
	"github.com/Protofarm/better-goth/pb"
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
	jwtSecret := os.Getenv("JWT_SECRET")

	google, err := providers.NewGoogleProvider(
		clientid,
		clientsecret,
		"http://localhost:8080/callback/google",
		[]string{},
	)

	if err != nil {
		log.Fatal(err)
	}

	auth, err := bettergoth.NewAuth([]byte(jwtSecret))
	if err != nil {
		log.Fatal(err)
	}

	auth.SetUserHandler(bettergoth.UserHandlerFunc(func(ctx context.Context, user *pb.User) error {
		log.Printf("authenticated user: %s", user.String())
		return nil
	}))

	auth.AddProvider(google)

	// Example custom provider (OIDC issuer based):
	// custom, err := providers.NewProvider(
	// 	"myprovider",
	// 	"https://issuer.example.com",
	// 	os.Getenv("MY_PROVIDER_CLIENT_ID"),
	// 	os.Getenv("MY_PROVIDER_CLIENT_SECRET"),
	// 	"http://localhost:8080/callback/myprovider",
	// 	[]string{"offline_access"},
	// )
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// auth.AddProvider(custom)

	bettergoth.RegisterRoutes(mux, auth)
	mux.Handle("/me", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := bettergoth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(user.Subject))
	})))

	log.Println("Server running on :8080")
	http.ListenAndServe(":8080", mux)
}
