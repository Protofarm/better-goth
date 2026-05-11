package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
	"github.com/golang-jwt/jwt/v5"
)

func IntrospectionHandler(s *store.Store, pubKey *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			errs.HTTPError(w, errs.JSONErrIntrospectionMethodNotAllowed, http.StatusMethodNotAllowed)
			return
		}

		// RFC 7662 Section 2.1: client authentication is required for introspection.
		clientID, clientSecret := extractClientCredentials(r)
		if clientID == "" {
			errs.HTTPError(w, errs.JSONErrIntrospectionInvalidRequest, http.StatusBadRequest)
			return
		}

		client, err := s.GetClient(clientID)
		if err != nil || client.ClientSecret != clientSecret {
			errs.HTTPError(w, errs.JSONErrIntrospectionInvalidRequest, http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			errs.HTTPError(w, errs.JSONErrIntrospectionInvalidRequest, http.StatusBadRequest)
			return
		}

		token := r.Form.Get("token")
		if token == "" {
			errs.HTTPError(w, errs.JSONErrIntrospectionInvalidRequest, http.StatusBadRequest)
			return
		}

		token_type_hint := r.Form.Get("token_type_hint")
		res := &introspectionResponse{Active: false}

		// RFC 7662 Section 2.1: extend the search across supported token types.
		var tok *models.Token
		switch token_type_hint {
		case "refresh_token":
			tok, err = s.GetByRefreshToken(token)
			if err == nil && tok.ClientID != clientID {
				json.NewEncoder(w).Encode(res)
				return
			}
			if err != nil {
				tok, err = s.GetByAccessToken(token)
				if err == nil && tok.ClientID != clientID {
					json.NewEncoder(w).Encode(res)
					return
				}
			}
		default: // handle access_token and default
			tok, err = s.GetByAccessToken(token)
			if err == nil && tok.ClientID != clientID {
				json.NewEncoder(w).Encode(res)
				return
			}
			if err != nil {
				tok, err = s.GetByRefreshToken(token)
				if err == nil && tok.ClientID != clientID {
					json.NewEncoder(w).Encode(res)
					return
				}
			}
		}

		if err != nil || tok == nil || time.Now().After(tok.ExpiresAt) {
			json.NewEncoder(w).Encode(res)
			return
		}

		jwtToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %s", t.Header["alg"])
			}
			return pubKey, nil
		}, jwt.WithValidMethods([]string{"RS256"}))

		if err != nil || !jwtToken.Valid {
			json.NewEncoder(w).Encode(res)
			return
		}

		claims, ok := jwtToken.Claims.(jwt.MapClaims)
		if !ok {
			json.NewEncoder(w).Encode(res)
			return
		}
		res.Active = true
		res.Scope = tok.Scope
		res.ClientId = tok.ClientID
		res.TokenType = tok.TokenType

		exp, err := claims.GetExpirationTime()
		if err == nil {
			res.Exp = exp.Unix()
		}
		iat, err := claims.GetIssuedAt()
		if err == nil {
			res.Iat = iat.Unix()
		}
		sub, err := claims.GetSubject()
		if err == nil {
			res.Sub = sub
		}
		aud, err := claims.GetAudience()
		if err == nil && len(aud) > 0 {
			res.Aud = aud[0]
		}
		iss, err := claims.GetIssuer()
		if err == nil {
			res.Iss = iss
		}
		_ = json.NewEncoder(w).Encode(res)
	}
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
