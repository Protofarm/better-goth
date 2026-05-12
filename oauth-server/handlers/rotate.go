package handlers

import (
	"encoding/json"
	"net/http"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"

	"github.com/Protofarm/better-goth/oauth-server/keys"
)

func RotateHandler(km *keys.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(errs.NewErrorResponse(
				errs.CodeMethodNotAllowed,
				errs.MsgOnlyPostAllowed,
			))
			return
		}

		if err := km.Rotate(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(errs.NewErrorResponse(
				errs.CodeServerError,
				err.Error(),
			))
			return
		}

		active := km.GetActiveKey()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "rotated",
			"kid":    active.Kid,
		})

	}
}
