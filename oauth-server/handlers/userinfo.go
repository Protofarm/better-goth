package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/middleware"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

// UserInfoHandler serves GET /userinfo.
func UserInfoHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userID string

		if claims, ok := middleware.ClaimsFromContext(r.Context()); ok {
			sub, _ := claims["sub"].(string)
			userID = sub
		}

		if userID == "" {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				errs.WriteError(w, http.StatusUnauthorized, errs.CodeMissingToken, errs.ResourceErrorMessages[errs.CodeMissingToken])
				return
			}
			raw := strings.TrimPrefix(authHeader, "Bearer ")
			tok, err := s.GetByAccessToken(raw)
			if err != nil || time.Now().After(tok.ExpiresAt) {
				errs.WriteError(w, http.StatusUnauthorized, errs.CodeInvalidToken, errs.ResourceErrorMessages[errs.CodeInvalidToken])
				return
			}
			userID = tok.UserID
		}

		user, err := s.GetUserByID(userID)
		if err != nil {
			errs.HTTPError(w, errs.JSONErrUserNotFound, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            user.ID,
			"name":           user.Name,
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"picture":        user.AvatarURL,
		}); err != nil {
			log.Printf("failed to write userinfo response: %v", err)
		}
	}
}
