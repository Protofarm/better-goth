package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	errs "github.com/Protofarm/better-goth/internal/oauth-server/errors"

	"github.com/Protofarm/better-goth/internal/oauth-server/keys"
)

func RotateHandler(km *keys.KeyManager, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(adminToken) == "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			errs.HTTPError(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
			return
		}

		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
		if subtle.ConstantTimeCompare([]byte(got), []byte(adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if err := km.Rotate(); err != nil {
			errs.HTTPError(w, errs.JSONErrInternalServer, http.StatusInternalServerError)
			return
		}

		active := km.GetActiveKey()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status": "rotated",
			"kid":    active.Kid,
		}); err != nil {
			log.Printf("failed to write rotate response: %v", err)
		}
	}
}
