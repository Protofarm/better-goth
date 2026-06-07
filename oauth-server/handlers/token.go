package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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

		client, ok := authenticateTokenClient(w, r, s, issuer)
		if !ok {
			return
		}

		tok, errCode, err := issueTokenForGrant(s, r, grantType, client)
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

func authenticateTokenClient(w http.ResponseWriter, r *http.Request, s *store.Store, issuer string) (*models.Client, bool) {

	// RFC 7523 private_key_jwt
	if r.FormValue("client_assertion") != "" {
		client, err := authenticatePrivateKeyJWT(r, s, issuer)
		if err != nil {
			errs.TokenError(w, errs.CodeInvalidClient, err.Error())
			return nil, false
		}

		return client, true
	}

	// client_secret_basic + client_secret_post
	clientID, clientSecret := extractClientCredentials(r)

	if clientID == "" {
		errs.TokenError(w, errs.CodeInvalidRequest, errs.MsgClientIDRequired)
		return nil, false
	}

	client, err := s.GetClient(clientID)
	if err != nil || client.ClientSecret != clientSecret {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		errs.TokenError(w, errs.CodeInvalidClient, errs.MsgClientAuthFailed)
		return nil, false
	}

	return client, true
}

func authenticatePrivateKeyJWT(r *http.Request, s *store.Store, issuer string) (*models.Client, error) {
	assertion, err := validateClientAssertionRequest(r)
	if err != nil {
		return nil, err
	}
	claims, err := parseUnverifiedAssertion(assertion)
	if err != nil {
		return nil, err
	}

	clientID, err := validateAssertionClaims(claims, issuer)
	if err != nil {
		return nil, err
	}

	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf(errs.MsgUnknownClient)
	}

	clientPublicKey, err := fetchPublicKey(client.PublicKeyEndpoint, assertion)
	if err != nil {
		return nil, fmt.Errorf(errs.MsgInvalidClientPublicKey)
	}

	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(clientPublicKey))
	if err != nil {
		return nil, fmt.Errorf(errs.MsgInvalidClientPublicKey)
	}

	if err := verifyAssertionSignature(assertion, pubKey); err != nil {
		return nil, err
	}

	return client, nil
}

func validateClientAssertionRequest(r *http.Request) (string, error) {
	assertionType := r.FormValue("client_assertion_type")
	if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return "", fmt.Errorf(errs.MsgInvalidClientAssertionType)
	}

	assertion := r.FormValue("client_assertion")

	if assertion == "" {
		return "", fmt.Errorf(errs.MsgMissingClientAssertion)
	}

	return assertion, nil
}
func parseUnverifiedAssertion(assertion string) (jwt.MapClaims, error) {
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf(errs.MsgInvalidJWTAssertion)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf(errs.MsgInvalidJWTClaims)
	}

	return claims, nil
}
func validateAssertionClaims(claims jwt.MapClaims, issuer string) (string, error) {
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	if iss == "" || sub == "" {
		return "", fmt.Errorf(errs.MsgMissingIssSub)
	}

	if iss != sub {
		return "", fmt.Errorf(errs.MsgIssSubMismatch)
	}

	expectedAudience := strings.TrimRight(issuer, "/") + "/oauth/token"

	if aud != expectedAudience {
		return "", fmt.Errorf(errs.MsgInvalidJWTAudience)
	}

	expFloat, ok := claims["exp"].(float64)

	if !ok {
		return "", fmt.Errorf(errs.MsgMissingJWTExp)
	}
	if time.Now().Unix() > int64(expFloat) {
		return "", fmt.Errorf(errs.MsgJWTExpired)
	}

	return iss, nil
}
func verifyAssertionSignature(assertion string, pubKey interface{}) error {
	token, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf(errs.MsgInvalidSigningMethod)
		}
		return pubKey, nil
	},
	)
	if err != nil {
		return fmt.Errorf(errs.MsgJWTVerificationFailed)
	}
	if !token.Valid {
		return fmt.Errorf(errs.MsgInvalidJWT)
	}
	return nil
}
func issueTokenForGrant(s *store.Store, r *http.Request, grantType string, client *models.Client) (*models.Token, string, error) {
	switch grantType {
	case "authorization_code":
		return handleAuthorizationCode(s, r, client)
	case "refresh_token":
		return handleRefreshToken(s, r)
	case "client_credentials":
		return handleClientCredentials(client, r.FormValue("scope"))
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
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func shouldIncludeIDToken(tok *models.Token, grantType string) bool {
	return grantType == "authorization_code" && scopeIncludes(tok.Scope, "openid")
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

func handleAuthorizationCode(s *store.Store, r *http.Request, client *models.Client) (*models.Token, string, error) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	verifier := r.FormValue("code_verifier")

	// RFC 6749 Section 4.1.3: code parameter is required
	if code == "" {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgCodeParamRequired)
	}

	authCode, err := s.PopCode(code) // also deletes it (single-use)
	if err != nil {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgInvalidAuthCode)
	}
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgAuthCodeExpired)
	}
	if authCode.ClientID != client.ID {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgCodeClientMismatch)
	}
	if authCode.RedirectURI != redirectURI {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgRedirectURIMismatch)
	}
	if authCode.CodeChallenge == "" {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgPkceRequired)
	}

	if verifier == "" {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgCodeVerifierRequired)
	}

	if authCode.CodeChallengeMethod != "S256" {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgS256OnlyErrorMsg)
	}

	if !verifyPKCE(authCode.CodeChallenge, verifier) {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgVerifierMismatch)
	}

	scope, err := resolveRequestedScope(r.FormValue("scope"), strings.Fields(authCode.Scope), authCode.Scope)
	if err != nil {
		return nil, errs.CodeInvalidScope, err
	}

	tok := newToken(authCode.UserID, client.ID, scope)
	tok.Nonce = authCode.Nonce
	return tok, "", nil
}

func handleRefreshToken(s *store.Store, r *http.Request) (*models.Token, string, error) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgRefreshTokenParamRequired)
	}

	old, err := s.GetByRefreshToken(refreshToken)
	if err != nil {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgInvalidRefreshToken)
	}

	if time.Now().After(old.ExpiresAt) {
		return nil, errs.CodeInvalidGrant, fmt.Errorf(errs.MsgRefreshTokenExpired)
	}

	scope, err := resolveRequestedScope(r.FormValue("scope"), strings.Fields(old.Scope), old.Scope)
	if err != nil {
		return nil, errs.CodeInvalidScope, err
	}

	//revoke old refresh token
	s.RevokeRefreshToken(refreshToken)

	// RFC 6749 Section 6: Refresh token rotation (implicit revocation of old token)
	// Generate new token pair
	tok := newToken(old.UserID, old.ClientID, scope)
	tok.Nonce = old.Nonce
	return tok, "", nil
}

func handleClientCredentials(client *models.Client, requestedScope string) (*models.Token, string, error) {
	scope, err := resolveRequestedScope(requestedScope, client.Scopes, strings.Join(client.Scopes, " "))
	if err != nil {
		return nil, errs.CodeInvalidScope, err
	}

	t := newToken(client.UserID, client.ID, scope)
	t.RefreshToken = "" // not issued for client_credentials
	return t, "", nil
}

func newToken(userID, clientID, scope string) *models.Token {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random token bytes: %v", err))
	}
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
		"picture":        user.Picture,
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

// TODO: implement caching on jwks response
func fetchPublicKey(publicKeyEndpoint, assertion string) (string, error) {
	assertionClaims, _, err := jwt.NewParser().ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return "", nil
	}
	kid, _ := assertionClaims.Header["kid"].(string)

	req, err := http.NewRequest("GET", publicKeyEndpoint, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	type JWK struct {
		Kty string   `json:"kty"`
		Kid string   `json:"kid"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5c []string `json:"x5c"`
	}

	type JWKS struct {
		Keys []JWK `json:"keys"`
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return "", err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			if len(key.X5c) > 0 {
				return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", key.X5c[0]), nil
			}
			return reconstructRSAPublicKeyPEM(key.N, key.E)
		}
	}
	return "", fmt.Errorf("Unable to fetch key")
}

// ai-generated slop
func reconstructRSAPublicKeyPEM(n, e string) (string, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return "", err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return "", err
	}

	var eInt big.Int
	eInt.SetBytes(eBytes)

	var nInt big.Int
	nInt.SetBytes(nBytes)

	pubKey := &rsa.PublicKey{
		N: &nInt,
		E: int(eInt.Int64()),
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}
