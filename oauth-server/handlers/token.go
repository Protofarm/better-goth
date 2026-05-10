package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

// TokenHandler handles OAuth 2.0 token requests.
// It supports authorization_code, refresh_token, and client_credentials grant types.
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

		grantType := r.FormValue("grant_type")
		if grantType == "" {
			tokenError(w, "invalid_request", "grant_type parameter is required")
			return
		}

		clientID, clientSecret := extractClientCredentials(r)
		if clientID == "" {
			tokenError(w, "invalid_request", "client_id is required")
			return
		}

		client, err := s.GetClient(r.Context(), clientID)
		if err != nil || client.ClientSecret != clientSecret {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			tokenError(w, "invalid_client", "client authentication failed")
			return
		}

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
			tokenError(w, "server_error", "failed to sign access token")
			return
		}
		tok.AccessToken = accessJWT
		s.SaveToken(r.Context(), tok)

		resp := map[string]interface{}{
			"access_token":  tok.AccessToken,
			"token_type":    "Bearer",
			"expires_in":    tok.ExpiresIn,
			"refresh_token": tok.RefreshToken,
			"scope":         tok.Scope,
		}

		if strings.Contains(tok.Scope, "openid") || grantType == "authorization_code" {
			if idToken, err := signIDToken(r.Context(), tok, s, privateKey, issuer); err == nil {
				resp["id_token"] = idToken
			}
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		json.NewEncoder(w).Encode(resp)
	}
}

// handleAuthorizationCode handles the authorization_code grant type.
func handleAuthorizationCode(s *store.Store, r *http.Request, clientID string) (*models.Token, error) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")

	// RFC 6749 Section 4.1.3: code parameter is required
	if code == "" {
		return nil, fmt.Errorf("code parameter is required")
	}

	authCode, err := s.PopCode(r.Context(), code) // also deletes it (single-use)
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
	// OAuth 2.1: PKCE is mandatory
	if authCode.CodeChallenge == "" {
		return nil, fmt.Errorf("PKCE (code_challenge) was missing in authorization request")
	}

	if verifier == "" {
		return nil, fmt.Errorf("code_verifier is required for authorization_code grant (mandatory per OAuth 2.1)")
	}

	// OAuth 2.1: S256 is the only allowed code_challenge_method
	if authCode.CodeChallengeMethod != "S256" {
		return nil, fmt.Errorf("unsupported code_challenge_method: only 'S256' is allowed")
	}

	if !verifyPKCE(authCode.CodeChallenge, verifier) {
		return nil, fmt.Errorf("code_verifier does not match code_challenge")
	}

	tok := newToken(authCode.UserID, clientID, authCode.Scope)
	tok.Nonce = authCode.Nonce
	return tok, nil
}

// handleRefreshToken handles the refresh_token grant type.
func handleRefreshToken(s *store.Store, r *http.Request) (*models.Token, error) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token parameter is required")
	}

	old, err := s.GetByRefreshToken(r.Context(), refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if time.Now().After(old.ExpiresAt) {
		return nil, fmt.Errorf("refresh token expired")
	}
	//revoke old refresh token
	s.RevokeRefreshToken(r.Context(), refreshToken)

	// RFC 6749 Section 6: Refresh token rotation (implicit revocation of old token)
	// Generate new token pair
	tok := newToken(old.UserID, old.ClientID, old.Scope)
	tok.Nonce = old.Nonce
	return tok, nil
}

// handleClientCredentials handles the client_credentials grant type.
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
// signJWT creates a signed RS256 JWT for the access token.
func signJWT(tok *models.Token, key *rsa.PrivateKey, issuer string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       tok.UserID,
		"aud":       tok.ClientID,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(),
		"scope":     tok.Scope,
		"token_use": "access",
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

// extractClientCredentials supports both HTTP Basic Auth and form body.
// extractClientCredentials extracts client ID and secret from the request.
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

// verifyPKCE verifies code_verifier against code_challenge per RFC 7636
// verifyPKCE verifies the code_verifier against the code_challenge using S256.
func verifyPKCE(challenge, verifier string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// signIDToken creates a signed RS256 JWT using the token metadata as OIDC claims,
// including nonce (if provided) and at_hash (hash of access token).
// signIDToken creates a signed RS256 JWT for the ID token.
func signIDToken(ctx context.Context, tok *models.Token, s *store.Store, key *rsa.PrivateKey, issuer string) (string, error) {
	now := time.Now()

	user, err := s.GetUserByID(ctx, tok.UserID)
	if err != nil {
		return "", fmt.Errorf("user not found for id_token claims")
	}

	// Extract given_name from name
	givenName := ""
	if user.Name != "" {
		parts := strings.Split(user.Name, " ")
		givenName = parts[0]
	}

	hash := sha256.Sum256([]byte(tok.AccessToken))
	atHash := base64.RawURLEncoding.EncodeToString(hash[:len(hash)/2])

	claims := jwt.MapClaims{
		"iss":            issuer,
		"sub":            tok.UserID,
		"aud":            tok.ClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Duration(tok.ExpiresIn) * time.Second).Unix(),
		"token_use":      "id",
		"auth_time":      now.Unix(),
		"azp":            tok.ClientID,
		"picture":        user.AvatarURL.String(),
		"email":          user.Email,
		"email_verified": false,
		"name":           user.Name,
		"given_name":     givenName,
		"at_hash":        atHash,
	}

	// OpenID Connect Core: nonce claim is REQUIRED if nonce was present in the authorization request
	if tok.Nonce != "" {
		claims["nonce"] = tok.Nonce
	}

	if user.Email != "" {
		claims["email_verified"] = true
	}

	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}
