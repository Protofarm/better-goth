package oauthserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Store errors
const (
	ErrInvalidCredentials   = "invalid credentials"
	ErrUserNotFound         = "user not found"
	ErrClientNotFound       = "client not found"
	ErrCodeNotFound         = "code not found"
	ErrAccessTokenNotFound  = "access token not found"
	ErrRefreshTokenNotFound = "refresh token not found"
	ErrUsernameExists       = "username already exists"
	ErrEmailRegistered      = "email already registered"
	ErrUnableToCreateUser   = "unable to create user"
)

// OAuth 2.0 Error Codes (RFC 6749)
const (
	ErrCodeInvalidRequest         = "invalid_request"
	ErrCodeInvalidClient          = "invalid_client"
	ErrCodeInvalidGrant           = "invalid_grant"
	ErrCodeUnauthorizedClient     = "unauthorized_client"
	ErrCodeUnsupportedGrantType   = "unsupported_grant_type"
	ErrCodeUnsupportedResponseType = "unsupported_response_type"
	ErrCodeInvalidScope           = "invalid_scope"
	ErrCodeServerError            = "server_error"
	ErrCodeTemporarilyUnavailable = "temporarily_unavailable"
)

// OAuth 2.0 Authorization Endpoint Errors (RFC 6749 Section 4.1.2.1)
const (
	ErrCodeInvalidRedirectURI = "invalid_redirect_uri"
)

// OAuth 2.0 Token Endpoint Errors (RFC 6749 Section 5.2)
const (
	ErrCodeMethodNotAllowed = "method_not_allowed"
)

// OAuth 2.0 Resource Server Errors (RFC 6750)
const (
	ErrCodeMissingToken = "missing_token"
	ErrCodeInvalidToken = "invalid_token"
	ErrCodeInsufficientScope = "insufficient_scope"
)

// PKCE Errors (RFC 7636)
const (
	ErrCodePKCERequired = "pkce_required"
	ErrCodeInvalidVerifier = "invalid_verifier"
)

// User Info Error Codes (OIDC)
const (
	ErrCodeUnauthorized = "unauthorized"
	ErrCodeUserNotFound = "user_not_found"
)

// Introspection/Revocation Error Messages
const (
	ErrCodeUnsupportedTokenType = "unsupported_token_type"
)

// Detailed error messages for Token Endpoint
var TokenErrorMessages = map[string]string{
	ErrCodeMethodNotAllowed:     "only POST method is allowed",
	ErrCodeInvalidRequest:       "invalid request parameters",
	ErrCodeInvalidClient:        "client authentication failed",
	ErrCodeUnsupportedGrantType: "grant_type is not supported",
	ErrCodeInvalidGrant:         "invalid grant",
	ErrCodeServerError:          "server error occurred",
}

// Detailed error messages for Authorization Endpoint
var AuthErrorMessages = map[string]string{
	ErrCodeUnsupportedResponseType: "response_type must be 'code'",
	ErrCodeInvalidClient:           "client_id is invalid or missing",
	ErrCodeInvalidRedirectURI:      "redirect_uri is not registered",
	ErrCodeInvalidRequest:          "invalid request parameters",
	ErrCodeMissingToken:            "Authorization header must be Bearer <token>",
}

// Detailed error messages for Resource Server
var ResourceErrorMessages = map[string]string{
	ErrCodeMissingToken: "Authorization header must be Bearer <token>",
	ErrCodeInvalidToken: "Token validation failed",
}

// TokenError writes an OAuth 2.0 error response for the token endpoint
// RFC 6749 Section 5.2: Error Response
func TokenError(w http.ResponseWriter, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

// RedirectError writes an error response that redirects with error parameters
// RFC 6749 Section 4.1.2.1: Error Response
func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI, errCode, desc, state string) {
	dest, _ := url.Parse(redirectURI)
	p := url.Values{}
	p.Set("error", errCode)
	p.Set("error_description", desc)
	if state != "" {
		p.Set("state", state)
	}
	dest.RawQuery = p.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// WriteError writes an OAuth 2.0 error response for resource servers
// RFC 6750 Section 3: Error Response
func WriteError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s"`, errCode))
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, errCode, description)
}

// HTTPError writes a generic error response using http.Error
// Used for endpoints like introspection, revocation, userinfo when they need to return JSON errors
func HTTPError(w http.ResponseWriter, errJSON string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(errJSON))
}

// ErrorResponse represents a standardized OAuth 2.0 error response
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// NewErrorResponse creates a new error response with the given error code and description
func NewErrorResponse(errCode, description string) *ErrorResponse {
	return &ErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
	}
}

// Helper functions for common PKCE errors
const (
	PkceRequiredErrorMsg         = "PKCE (code_challenge) is required per OAuth 2.1"
	CodeVerifierRequiredErrorMsg = "code_verifier is required"
	S256OnlyErrorMsg             = "only S256 code_challenge_method is allowed"
	VerifierMismatchErrorMsg     = "code_verifier does not match code_challenge"
)

// Helper functions for common authorization code errors
const (
	CodeParamRequiredErrorMsg    = "code parameter is required"
	InvalidAuthCodeErrorMsg      = "invalid authorization code"
	AuthCodeExpiredErrorMsg      = "authorization code expired"
	CodeClientMismatchErrorMsg   = "code was not issued to this client"
	RedirectURIMismatchErrorMsg  = "redirect_uri mismatch"
)

// Helper functions for common refresh token errors
const (
	RefreshTokenParamRequiredErrorMsg = "refresh_token parameter is required"
	InvalidRefreshTokenErrorMsg        = "invalid refresh token"
	RefreshTokenExpiredErrorMsg        = "refresh token expired"
)

// Helper functions for common user errors
const (
	UserNotFoundForIDTokenErrorMsg = "user not found for id_token claims"
	UnexpectedSigningMethodErrorMsg = "unexpected signing method: %s"
)

// ValidateErrorCode checks if an error code is valid according to OAuth 2.0 specifications
func ValidateErrorCode(errCode string) bool {
	validCodes := map[string]bool{
		ErrCodeInvalidRequest:         true,
		ErrCodeInvalidClient:          true,
		ErrCodeInvalidGrant:           true,
		ErrCodeUnauthorizedClient:     true,
		ErrCodeUnsupportedGrantType:   true,
		ErrCodeUnsupportedResponseType: true,
		ErrCodeInvalidScope:           true,
		ErrCodeServerError:            true,
		ErrCodeTemporarilyUnavailable: true,
		ErrCodeInvalidRedirectURI:     true,
		ErrCodeMethodNotAllowed:       true,
		ErrCodeMissingToken:           true,
		ErrCodeInvalidToken:           true,
		ErrCodeInsufficientScope:      true,
		ErrCodeUnauthorized:           true,
		ErrCodeUserNotFound:           true,
	}
	return validCodes[errCode]
}

// GetErrorDescription returns a user-friendly error description based on the error code
func GetErrorDescription(errCode string, defaultDesc string) string {
	if desc, ok := TokenErrorMessages[errCode]; ok {
		return desc
	}
	if desc, ok := AuthErrorMessages[errCode]; ok {
		return desc
	}
	if desc, ok := ResourceErrorMessages[errCode]; ok {
		return desc
	}
	return defaultDesc
}

// IsTemporaryError checks if the error is temporary (server can retry)
func IsTemporaryError(errCode string) bool {
	tempErrors := map[string]bool{
		ErrCodeServerError:            true,
		ErrCodeTemporarilyUnavailable: true,
	}
	return tempErrors[errCode]
}

// IsPermanentError checks if the error is permanent (server should not retry)
func IsPermanentError(errCode string) bool {
	return ValidateErrorCode(errCode) && !IsTemporaryError(errCode)
}

// StoreErrorToOAuthError converts a store error to an OAuth 2.0 error code and description
func StoreErrorToOAuthError(storeErr string) (errCode, errDesc string) {
	storeErr = strings.ToLower(storeErr)

	switch {
	case strings.Contains(storeErr, "invalid credentials"):
		return ErrCodeInvalidGrant, "The provided credentials are invalid"
	case strings.Contains(storeErr, "user not found"):
		return ErrCodeInvalidGrant, "The user does not exist"
	case strings.Contains(storeErr, "client not found"):
		return ErrCodeInvalidClient, "The client does not exist"
	case strings.Contains(storeErr, "code not found"):
		return ErrCodeInvalidGrant, "The authorization code is invalid"
	case strings.Contains(storeErr, "access token not found"):
		return ErrCodeInvalidToken, "The access token is invalid"
	case strings.Contains(storeErr, "refresh token not found"):
		return ErrCodeInvalidGrant, "The refresh token is invalid"
	case strings.Contains(storeErr, "username already exists"):
		return ErrCodeInvalidRequest, "The username is already in use"
	case strings.Contains(storeErr, "email already registered"):
		return ErrCodeInvalidRequest, "The email is already registered"
	case strings.Contains(storeErr, "unable to create user"):
		return ErrCodeServerError, "Failed to create user"
	default:
		return ErrCodeServerError, "An error occurred"
	}
}
