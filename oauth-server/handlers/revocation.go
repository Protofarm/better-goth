package handlers

import (
	"net/http"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

func RevocationHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errs.HTTPError(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
			return
		}

		// RFC 7009 Section 2.1: The client also includes its authentication credentials
		clientID, clientSecret := extractClientCredentials(r)
		if clientID == "" {
			errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
			return
		}

		client, err := s.GetClient(clientID)
		if err != nil || client.ClientSecret != clientSecret {
			errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
			return
		}

		token := r.Form.Get("token")
		if token == "" {
			errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
			return
		}

		token_type_hint := r.Form.Get("token_type_hint")

		// RFC 7009 Section 2.1: MUST extend its search across all of its supported token types
		switch token_type_hint {
		case "refresh_token":
			tok, err := s.GetByRefreshToken(token)
			if err == nil {
				if tok.ClientID != clientID {
					w.WriteHeader(200)
					return
				}
				s.RevokeRefreshToken(token)
				break
			}
			tok, err = s.GetByAccessToken(token)
			if err == nil && tok.ClientID != clientID {
				w.WriteHeader(200)
				return
			}
			s.RevokeAccessToken(token)
		default: // handle access_token and default
			tok, err := s.GetByAccessToken(token)
			if err == nil {
				if tok.ClientID != clientID {
					w.WriteHeader(200)
					return
				}
				s.RevokeAccessToken(token)
				break
			}
			tok, err = s.GetByRefreshToken(token)
			if err == nil && tok.ClientID != clientID {
				w.WriteHeader(200)
				return
			}
			s.RevokeRefreshToken(token)
		}

		// RFC 7009 Section 2.2: invalid tokens do not cause an error response
		w.WriteHeader(200)
	}
}
