package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"

	"github.com/Protofarm/better-goth/oauth-server/keys"
)

func RotateHandler(km *keys.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errs.HTTPError(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
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
