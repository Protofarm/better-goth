package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/keys"
	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
	"github.com/golang-jwt/jwt/v5"
)

func IntrospectionHandler(s *store.Store, km *keys.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			errs.HTTPError(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
			return
		}

		clientID, ok := authenticateIntrospectionClient(w, r, s)
		if !ok {
			return
		}

		token, tokenTypeHint, ok := parseIntrospectionRequest(w, r)
		if !ok {
			return
		}

		res := introspectToken(s, km, clientID, token, tokenTypeHint)
		_ = json.NewEncoder(w).Encode(res)
	}
}

func authenticateIntrospectionClient(w http.ResponseWriter, r *http.Request, s *store.Store) (string, bool) {
	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
		return "", false
	}

	client, err := s.GetClient(clientID)
	if err != nil || client.ClientSecret != clientSecret {
		errs.HTTPError(w, errs.JSONErrInvalidRequest, http.StatusBadRequest)
		return "", false
	}

	return clientID, true
}

func parseIntrospectionRequest(w http.ResponseWriter, r *http.Request) (string, string, bool) {
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

func introspectToken(s *store.Store, km *keys.KeyManager, clientID, token, tokenTypeHint string) *introspectionResponse {
	res := &introspectionResponse{Active: false}

	tok, ok := lookupTokenForClient(s, clientID, token, tokenTypeHint)
	if !ok || time.Now().After(tok.ExpiresAt) {
		return res
	}

	claims, ok := parseJWTClaims(km, token)
	if !ok {
		return res
	}

	return activeIntrospectionResponse(tok, claims)
}

func lookupTokenForClient(s *store.Store, clientID, token, tokenTypeHint string) (*models.Token, bool) {
	for _, lookup := range tokenLookupOrder(s, tokenTypeHint) {
		tok, err := lookup(token)
		if err != nil {
			continue
		}
		if tok.ClientID != clientID {
			return nil, false
		}
		return tok, true
	}

	return nil, false
}

func tokenLookupOrder(s *store.Store, tokenTypeHint string) []func(string) (*models.Token, error) {
	if tokenTypeHint == "refresh_token" {
		return []func(string) (*models.Token, error){
			s.GetByRefreshToken,
			s.GetByAccessToken,
		}
	}

	return []func(string) (*models.Token, error){
		s.GetByAccessToken,
		s.GetByRefreshToken,
	}
}

func parseJWTClaims(km *keys.KeyManager, token string) (jwt.MapClaims, bool) {
	jwtToken, err := km.ParseJWT(token)
	if err != nil || !jwtToken.Valid {
		return nil, false
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	return claims, ok
}

func activeIntrospectionResponse(tok *models.Token, claims jwt.MapClaims) *introspectionResponse {
	res := &introspectionResponse{
		Active:    true,
		Scope:     tok.Scope,
		ClientId:  tok.ClientID,
		TokenType: tok.TokenType,
	}

	if exp, err := claims.GetExpirationTime(); err == nil {
		res.Exp = exp.Unix()
	}
	if iat, err := claims.GetIssuedAt(); err == nil {
		res.Iat = iat.Unix()
	}
	if sub, err := claims.GetSubject(); err == nil {
		res.Sub = sub
	}
	if aud, err := claims.GetAudience(); err == nil && len(aud) > 0 {
		res.Aud = aud[0]
	}
	if iss, err := claims.GetIssuer(); err == nil {
		res.Iss = iss
	}

	return res
}

type introspectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientId  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
}
