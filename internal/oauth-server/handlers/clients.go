package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	errs "github.com/Protofarm/better-goth/internal/oauth-server/errors"
	"github.com/Protofarm/better-goth/internal/oauth-server/middleware"
	"github.com/Protofarm/better-goth/internal/oauth-server/store"
)

type body struct {
	RegenerateSecret  bool     `json:"regenerate_secret"`
	PublicKeyEndpoint string   `json:"public_key_endpoint"`
	RedirectURIs      []string `json:"redirect_uris"`
	Scopes            []string `json:"scopes"`
}

func ClientHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userID string

		if claims, ok := middleware.ClaimsFromContext(r.Context()); ok {
			sub, _ := claims["sub"].(string)
			userID = sub
		}

		if userID == "" {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				errs.HTTPError(w, errs.JSONErrUnauthorized, http.StatusUnauthorized)
				return
			}
			raw := strings.TrimPrefix(authHeader, "Bearer ")
			tok, err := s.GetByAccessToken(raw)
			if err != nil || time.Now().After(tok.ExpiresAt) {
				errs.HTTPError(w, errs.JSONErrInvalidToken, http.StatusUnauthorized)
				return
			}
			userID = tok.UserID
		}

		switch r.Method {
		case http.MethodGet:
			client, err := s.GetClientByUserID(userID)
			if err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			client.ClientSecret = "" // Only show secret on creation or regeneration
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(client)

		case http.MethodPost:
			var reqBody body
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				log.Printf("Failed to decode request body: %v", err)
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			client, err := s.CreateClient(userID, reqBody.PublicKeyEndpoint, reqBody.Scopes, reqBody.RedirectURIs)
			if err != nil {
				log.Printf("Failed to create client for user %s: %v", userID, err)
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(client)

		case http.MethodPatch:
			var reqBody body
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				log.Printf("Failed to decode PATCH request body: %v", err)
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			log.Printf("PATCH request for user %s: regenerate=%v, endpoint=%s, scopes=%v, redirects=%v",
				userID, reqBody.RegenerateSecret, reqBody.PublicKeyEndpoint, reqBody.Scopes, reqBody.RedirectURIs)

			client, err := s.GetClientByUserID(userID)
			if err != nil {
				log.Printf("Failed to get client for user %s: %v", userID, err)
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			updatedClient, err := s.UpdateClient(client.ID, reqBody.PublicKeyEndpoint, reqBody.Scopes, reqBody.RedirectURIs, reqBody.RegenerateSecret)
			if err != nil {
				log.Printf("Failed to update client %s: %v", client.ID, err)
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			if !reqBody.RegenerateSecret {
				updatedClient.ClientSecret = "" // Hide secret if not regenerated
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(updatedClient)

		case http.MethodDelete:
			client, err := s.GetClientByUserID(userID)
			if err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			err = s.DeleteClient(client.ID)
			if err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			errs.HTTPError(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
		}
	}
}
