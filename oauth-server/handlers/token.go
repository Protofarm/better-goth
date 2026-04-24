package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

func TokenHandler(s *store.Store, privateKey *rsa.PrivateKey, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			tokenError(w, "invalid_request", "could not parse form body")
			return
		}

		clientID, clientSecret := extractClientCredentials(r)
		client, err := s.GetClient(clientID)
		if err != nil || client.ClientSecret != clientSecret {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			tokenError(w, "invalid_client", "client authentication failed")
			return
		}

		grantType := r.FormValue("grant_type")

		var tok *models.Token

		switch grantType {
		case "authorization_code":
			tok, err = handleAuthorizationCode(s, r, clientID)
		case "refresh_token":
			tok, err = handleRefreshToken(s, r)
		case "client_credentials":
			tok, err = handleClientCredentials(clientID)
		default:
			tokenError(w, "unsupported_grant_type", fmt.Sprintf("grant_type %q is not supported", grantType))
			return
		}

		if err != nil {
			tokenError(w, "invalid_grant", err.Error())
			return
		}

		accessJWT, err := signJWT(tok, privateKey, issuer)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		tok.AccessToken = accessJWT
		s.SaveToken(tok)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  tok.AccessToken,
			"token_type":    "Bearer",
			"expires_in":    tok.ExpiresIn,
			"refresh_token": tok.RefreshToken,
			"scope":         tok.Scope,
		})
	}
}

func handleAuthorizationCode(s *store.Store, r *http.Request, clientID string) (*models.Token, error) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")

	authCode, err := s.PopCode(code) // also deletes it (single-use)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code")
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("code was not issued to this client")
	}
	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	//PKCE verification
	if authCode.CodeChallenge != "" {
		if verifier == "" {
			return nil, fmt.Errorf("code_verifier is required")
		}
		if !verifyPKCE(authCode.CodeChallengeMethod, authCode.CodeChallenge, verifier) {
			return nil, fmt.Errorf("code_verifier does not match code_challenge")
		}
	}

	return newToken(authCode.UserID, clientID, authCode.Scope), nil
}

func handleRefreshToken(s *store.Store, r *http.Request) (*models.Token, error) {
	old, err := s.GetByRefreshToken(r.FormValue("refresh_token"))
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}
	// Rotate: old token is revoked implicitly because we overwrite with a new one
	return newToken(old.UserID, old.ClientID, old.Scope), nil
}

func handleClientCredentials(clientID string) (*models.Token, error) {
	t := newToken(clientID, clientID, "read")
	t.RefreshToken = "" // not issued for client_credentials
	return t, nil
}

func newToken(userID, clientID, scope string) *models.Token {
	b := make([]byte, 32)
	rand.Read(b)
	return &models.Token{
		AccessToken:  hex.EncodeToString(b), // overwritten by JWT after signing
		RefreshToken: hex.EncodeToString(b[:16]),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        scope,
		UserID:       userID,
		ClientID:     clientID,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
}

// signJWT creates a signed RS256 JWT using the token metadata as claims.
func signJWT(tok *models.Token, key *rsa.PrivateKey, issuer string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       tok.UserID,
		"aud":       jwt.ClaimStrings{tok.ClientID},
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(),
		"scope":     tok.Scope,
		"token_use": "access",
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

// extractClientCredentials supports both HTTP Basic Auth and form body.
func extractClientCredentials(r *http.Request) (id, secret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func tokenError(w http.ResponseWriter, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
