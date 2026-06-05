package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/middleware"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

type body struct {
	RegenerateSecret  bool     `json:"regenerate_client_secret"`
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
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(client)

		case http.MethodPost:
			var reqBody body
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			err := s.CreateClient(userID, reqBody.PublicKeyEndpoint, reqBody.Scopes, reqBody.RedirectURIs)
			if err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)

		case http.MethodPatch:
			var reqBody body
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			client, err := s.GetClientByUserID(userID)
			if err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			err = s.UpdateClient(client.ID, reqBody.PublicKeyEndpoint, reqBody.Scopes, reqBody.RedirectURIs, reqBody.RegenerateSecret)
			if err != nil {
				errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)

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
