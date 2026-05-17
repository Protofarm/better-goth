package handlers

import (
	"net/http"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

func RevocationHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errs.HTTPError(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
			return
		}

		clientID, ok := authenticateRevocationClient(w, r, s)
		if !ok {
			return
		}

		token, tokenTypeHint, ok := parseRevocationRequest(w, r)
		if !ok {
			return
		}

		revokeTokenForClient(s, clientID, token, tokenTypeHint)
		w.WriteHeader(200)
	}
}

type tokenRevocationLookup struct {
	find   func(string) (*models.Token, error)
	revoke func(string)
}

func authenticateRevocationClient(w http.ResponseWriter, r *http.Request, s *store.Store) (string, bool) {
	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		errs.InvalidClientError(w, errs.MsgClientAuthFailed)
		return "", false
	}

	client, err := s.GetClient(clientID)
	if err != nil || client.ClientSecret != clientSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		errs.InvalidClientError(w, errs.MsgClientAuthFailed)
		return "", false
	}

	return clientID, true
}

func parseRevocationRequest(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if err := r.ParseForm(); err != nil {
		errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
		return "", "", false
	}

	token := r.Form.Get("token")
	if token == "" {
		errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
		return "", "", false
	}

	return token, r.Form.Get("token_type_hint"), true
}

func revokeTokenForClient(s *store.Store, clientID, token, tokenTypeHint string) {
	for _, lookup := range tokenRevocationOrder(s, tokenTypeHint) {
		tok, err := lookup.find(token)
		if err != nil {
			continue
		}
		if tok.ClientID != clientID {
			return
		}

		lookup.revoke(token)
		return
	}
}

func tokenRevocationOrder(s *store.Store, tokenTypeHint string) []tokenRevocationLookup {
	if tokenTypeHint == "refresh_token" {
		return []tokenRevocationLookup{
			{find: s.GetByRefreshToken, revoke: s.RevokeRefreshToken},
			{find: s.GetByAccessToken, revoke: s.RevokeAccessToken},
		}
	}

	return []tokenRevocationLookup{
		{find: s.GetByAccessToken, revoke: s.RevokeAccessToken},
		{find: s.GetByRefreshToken, revoke: s.RevokeRefreshToken},
	}
}
