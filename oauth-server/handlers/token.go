package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/keys"
	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

func TokenHandler(s *store.Store, km *keys.KeyManager, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			errs.TokenError(w, errs.CodeMethodNotAllowed, errs.MsgOnlyPostAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			errs.TokenError(w, errs.CodeInvalidRequest, errs.MsgCouldNotParseForm)
			return
		}

		grantType, ok := parseGrantType(w, r)
		if !ok {
			return
		}

		clientID, ok := authenticateTokenClient(w, r, s)
		if !ok {
			return
		}

		tok, errCode, err := issueTokenForGrant(s, r, grantType, clientID)
		if err != nil {
			errs.TokenError(w, errCode, err.Error())
			return
		}

		privateKeyInfo := km.GetActiveKey()
		if err := signAndStoreToken(s, tok, privateKeyInfo, issuer); err != nil {
			errs.TokenError(w, errs.CodeServerError, errs.MsgServerError)
			return
		}

		writeTokenResponse(w, s, tok, privateKeyInfo, issuer, grantType)
	}
}

func parseGrantType(w http.ResponseWriter, r *http.Request) (string, bool) {
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		errs.TokenError(w, errs.CodeInvalidRequest, errs.MsgGrantTypeRequired)
		return "", false
	}

	return grantType, true
}

func authenticateTokenClient(w http.ResponseWriter, r *http.Request, s *store.Store) (string, bool) {
	clientID, clientSecret := extractClientCredentials(r)
	if clientID == "" {
		errs.TokenError(w, errs.CodeInvalidRequest, errs.MsgClientIDRequired)
		return "", false
	}

	client, err := s.GetClient(clientID)
	if err != nil || client.ClientSecret != clientSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		errs.TokenError(w, errs.CodeInvalidClient, errs.MsgClientAuthFailed)
		return "", false
	}

	return clientID, true
}

func issueTokenForGrant(s *store.Store, r *http.Request, grantType, clientID string) (*models.Token, string, error) {
	switch grantType {
	case "authorization_code":
		tok, err := handleAuthorizationCode(s, r, clientID)
		return tok, errs.CodeInvalidGrant, err
	case "refresh_token":
		tok, err := handleRefreshToken(s, r)
		return tok, errs.CodeInvalidGrant, err
	case "client_credentials":
		tok, err := handleClientCredentials(clientID)
		return tok, errs.CodeInvalidGrant, err
	default:
		return nil, errs.CodeUnsupportedGrantType, fmt.Errorf("grant_type %q is not supported", grantType)
	}
}

func signAndStoreToken(s *store.Store, tok *models.Token, keyInfo keys.KeyInfo, issuer string) error {
	accessJWT, err := signJWT(tok, keyInfo, issuer)
	if err != nil {
		return err
	}

	tok.AccessToken = accessJWT
	s.SaveToken(tok)
	return nil
}

func writeTokenResponse(w http.ResponseWriter, s *store.Store, tok *models.Token, keyInfo keys.KeyInfo, issuer, grantType string) {
	resp := map[string]interface{}{
		"access_token":  tok.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    tok.ExpiresIn,
		"refresh_token": tok.RefreshToken,
		"scope":         tok.Scope,
	}

	if shouldIncludeIDToken(tok, grantType) {
		if idToken, err := signIDToken(tok, s, keyInfo, issuer); err == nil {
			resp["id_token"] = idToken
		}
	}

	writeTokenResponseHeaders(w)
	json.NewEncoder(w).Encode(resp)
}

func shouldIncludeIDToken(tok *models.Token, grantType string) bool {
	return strings.Contains(tok.Scope, "openid") || grantType == "authorization_code"
}

func writeTokenResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
}

func handleAuthorizationCode(s *store.Store, r *http.Request, clientID string) (*models.Token, error) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")

	// RFC 6749 Section 4.1.3: code parameter is required
	if code == "" {
		return nil, fmt.Errorf(errs.MsgCodeParamRequired)
	}

	authCode, err := s.PopCode(code) // also deletes it (single-use)
	if err != nil {
		return nil, fmt.Errorf(errs.MsgInvalidAuthCode)
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf(errs.MsgAuthCodeExpired)
	}
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf(errs.MsgCodeClientMismatch)
	}
	if authCode.RedirectURI != redirectURI {
		return nil, fmt.Errorf(errs.MsgRedirectURIMismatch)
	}
	if authCode.CodeChallenge == "" {
		return nil, fmt.Errorf(errs.MsgPkceRequired)
	}

	if verifier == "" {
		return nil, fmt.Errorf(errs.MsgCodeVerifierRequired)
	}

	if authCode.CodeChallengeMethod != "S256" {
		return nil, fmt.Errorf(errs.MsgS256OnlyErrorMsg)
	}

	if !verifyPKCE(authCode.CodeChallenge, verifier) {
		return nil, fmt.Errorf(errs.MsgVerifierMismatch)
	}

	tok := newToken(authCode.UserID, clientID, authCode.Scope)
	tok.Nonce = authCode.Nonce
	return tok, nil
}

func handleRefreshToken(s *store.Store, r *http.Request) (*models.Token, error) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		return nil, fmt.Errorf(errs.MsgRefreshTokenParamRequired)
	}

	old, err := s.GetByRefreshToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf(errs.MsgInvalidRefreshToken)
	}

	if time.Now().After(old.ExpiresAt) {
		return nil, fmt.Errorf(errs.MsgRefreshTokenExpired)
	}
	//revoke old refresh token
	s.RevokeRefreshToken(refreshToken)

	// RFC 6749 Section 6: Refresh token rotation (implicit revocation of old token)
	// Generate new token pair
	tok := newToken(old.UserID, old.ClientID, old.Scope)
	tok.Nonce = old.Nonce
	return tok, nil
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
func signJWT(tok *models.Token, keyInfo keys.KeyInfo, issuer string) (string, error) {
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
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyInfo.Kid
	return token.SignedString(keyInfo.GetPrivateKey())
}

// extractClientCredentials supports both HTTP Basic Auth and form body.
func extractClientCredentials(r *http.Request) (id, secret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

// verifyPKCE verifies code_verifier against code_challenge per RFC 7636
func verifyPKCE(challenge, verifier string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return computed == challenge
}

// signIDToken creates a signed RS256 JWT using the token metadata as OIDC claims,
// including nonce (if provided) and at_hash (hash of access token).
func signIDToken(tok *models.Token, s *store.Store, keyInfo keys.KeyInfo, issuer string) (string, error) {
	now := time.Now()

	user, err := s.GetUserByID(tok.UserID)
	if err != nil {
		return "", fmt.Errorf(errs.MsgUserNotFoundForIDToken)
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyInfo.Kid
	return token.SignedString(keyInfo.GetPrivateKey())
}
