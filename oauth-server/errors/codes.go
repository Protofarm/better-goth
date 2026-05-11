package errors

// OAuth 2.0 Error Codes (RFC 6749)
const (
	CodeInvalidRequest         = "invalid_request"
	CodeInvalidClient          = "invalid_client"
	CodeInvalidGrant           = "invalid_grant"
	CodeUnauthorizedClient     = "unauthorized_client"
	CodeUnsupportedGrantType   = "unsupported_grant_type"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeInvalidScope           = "invalid_scope"
	CodeServerError            = "server_error"
	CodeTemporarilyUnavailable = "temporarily_unavailable"
)

// OAuth 2.0 Authorization Endpoint Errors (RFC 6749 Section 4.1.2.1)
const (
	CodeInvalidRedirectURI = "invalid_redirect_uri"
)

// OAuth 2.0 Token Endpoint Errors (RFC 6749 Section 5.2)
const (
	CodeMethodNotAllowed = "method_not_allowed"
)

// OAuth 2.0 Resource Server Errors (RFC 6750)
const (
	CodeMissingToken     = "missing_token"
	CodeInvalidToken     = "invalid_token"
	CodeInsufficientScope = "insufficient_scope"
)

// PKCE Errors (RFC 7636)
const (
	CodePKCERequired   = "pkce_required"
	CodeInvalidVerifier = "invalid_verifier"
)

// User Info Error Codes (OIDC)
const (
	CodeUnauthorized = "unauthorized"
	CodeUserNotFound = "user_not_found"
)

// Introspection/Revocation Error Codes
const (
	CodeUnsupportedTokenType = "unsupported_token_type"
)
