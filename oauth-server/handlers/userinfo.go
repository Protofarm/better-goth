package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

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
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			raw := strings.TrimPrefix(authHeader, "Bearer ")
			tok, err := s.GetByAccessToken(raw)
			if err != nil || time.Now().After(tok.ExpiresAt) {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}
			userID = tok.UserID
		}

		user, err := s.GetUserByID(userID)
		if err != nil {
			http.Error(w, `{"error":"user_not_found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":        user.ID,
			"name":       user.Name,
			"email":      user.Email,
			"picture":    user.AvatarURL.String(), // OIDC standard field name
			"avatar_url": user.AvatarURL,          // also expose as avatar_url
		})
	}
}
