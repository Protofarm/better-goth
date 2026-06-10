package handlers

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Protofarm/better-goth/internal/oauth-server/keys"
	"github.com/Protofarm/better-goth/internal/oauth-server/store"
)

func GenerateEmailVerificationToken(userID string, km *keys.KeyManager, issuer string) (string, error) {
	keyInfo := km.GetActiveKey()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": userID,
		"pur": "email_verification",
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyInfo.Kid
	return token.SignedString(keyInfo.GetPrivateKey())
}

func VerifyEmailHandler(s *store.Store, km *keys.KeyManager, templatePath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		parsed, err := km.ParseJWT(tokenStr)
		if err != nil || !parsed.Valid {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		claims, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		pur, _ := claims["pur"].(string)
		if pur != "email_verification" {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		userID, _ := claims["sub"].(string)
		if userID == "" {
			http.Error(w, "Invalid or expired token", http.StatusBadRequest)
			return
		}

		if err := s.ConfirmUserEmail(userID); err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		user, err := s.GetUserByID(userID)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		log.Printf("email verified: sub=%s email=%s", userID, user.Email)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		tmpl, err := template.ParseFiles(templatePath)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, user)
	}
}
