package errors

// Store error messages
const (
	MsgInvalidCredentials   = "invalid credentials"
	MsgUserNotFound         = "user not found"
	MsgClientNotFound       = "client not found"
	MsgCodeNotFound         = "code not found"
	MsgAccessTokenNotFound  = "access token not found"
	MsgRefreshTokenNotFound = "refresh token not found"
	MsgUsernameExists       = "username already exists"
	MsgEmailRegistered      = "email already registered"
	MsgUnableToCreateUser   = "unable to create user"
)

// Authorization endpoint error messages
const (
	MsgUnsupportedResponseType = "response_type must be 'code'"
	MsgInvalidClientID         = "client_id is invalid or missing"
	MsgInvalidRedirectURI      = "redirect_uri is not registered"
	MsgStateRequired           = "state parameter is required"
	MsgCodeChallengeRequired   = "code_challenge parameter is required (PKCE is mandatory per OAuth 2.1)"
	MsgOnlyS256Allowed         = "only S256 code_challenge_method is allowed"
)

// Token endpoint error messages
const (
	MsgOnlyPostAllowed       = "only POST method is allowed"
	MsgCouldNotParseForm     = "could not parse form body"
	MsgGrantTypeRequired     = "grant_type parameter is required"
	MsgClientIDRequired      = "client_id is required"
	MsgClientAuthFailed      = "client authentication failed"
	MsgGrantTypeNotSupported = "grant_type is not supported"
)

// PKCE error messages
const (
	MsgPkceRequired         = "PKCE (code_challenge) is required per OAuth 2.1"
	MsgCodeVerifierRequired = "code_verifier is required"
	MsgS256OnlyErrorMsg     = "only S256 code_challenge_method is allowed"
	MsgVerifierMismatch     = "code_verifier does not match code_challenge"
)

// Authorization code error messages
const (
	MsgCodeParamRequired   = "code parameter is required"
	MsgInvalidAuthCode     = "invalid authorization code"
	MsgAuthCodeExpired     = "authorization code expired"
	MsgCodeClientMismatch  = "code was not issued to this client"
	MsgRedirectURIMismatch = "redirect_uri mismatch"
)

// Refresh token error messages
const (
	MsgRefreshTokenParamRequired = "refresh_token parameter is required"
	MsgInvalidRefreshToken       = "invalid refresh token"
	MsgRefreshTokenExpired       = "refresh token expired"
)

// Resource server error messages
const (
	MsgMissingToken          = "Authorization header must be Bearer <token>"
	MsgTokenValidationFailed = "Token validation failed"
)

// Signing/Parsing error messages
const (
	MsgUnexpectedSigningMethod = "unexpected signing method: %s"
	MsgUserNotFoundForIDToken  = "user not found for id_token claims"
)

// Userinfo endpoint error messages
const (
	MsgUserInfoUnauthorized = "unauthorized"
	MsgUserInfoTokenInvalid = "invalid_token"
	MsgUserInfoNotFound     = "user_not_found"
)

// Generic error messages
const (
	MsgServerError      = "server error occurred"
	MsgInvalidRequest   = "invalid request parameters"
	MsgMethodNotAllowed = "method not allowed"
)

// TokenErrorMessages maps error codes to descriptions for token endpoint
var TokenErrorMessages = map[string]string{
	CodeMethodNotAllowed:     MsgOnlyPostAllowed,
	CodeInvalidRequest:       MsgInvalidRequest,
	CodeInvalidClient:        MsgClientAuthFailed,
	CodeUnsupportedGrantType: MsgGrantTypeNotSupported,
	CodeInvalidGrant:         "invalid grant",
	CodeServerError:          MsgServerError,
}

// AuthErrorMessages maps error codes to descriptions for authorization endpoint
var AuthErrorMessages = map[string]string{
	CodeUnsupportedResponseType: MsgUnsupportedResponseType,
	CodeInvalidClient:           MsgInvalidClientID,
	CodeInvalidRedirectURI:      MsgInvalidRedirectURI,
	CodeInvalidRequest:          MsgInvalidRequest,
	CodeMissingToken:            MsgMissingToken,
}

// ResourceErrorMessages maps error codes to descriptions for resource servers
var ResourceErrorMessages = map[string]string{
	CodeMissingToken: MsgMissingToken,
	CodeInvalidToken: MsgTokenValidationFailed,
}

// Generic JSON error responses
const (
	JSONErrInternalServer   = `{"error":"internal_server_error"}`
	JSONErrMethodNotAllowed = `{"error":"method_not_allowed"}`
	JSONErrInvalidRequest   = `{"error":"invalid_request"}`
)

// JSON error responses for authorization endpoint
const (
	JSONErrUnsupportedResponseType = `{"error":"unsupported_response_type","error_description":"response_type must be 'code'"}`
	JSONErrInvalidClient           = `{"error":"invalid_client","error_description":"client_id is invalid or missing"}`
	JSONErrInvalidRedirectURI      = `{"error":"invalid_redirect_uri","error_description":"redirect_uri is not registered"}`
	JSONErrUnauthorized            = `{"error":"unauthorized"}`
	JSONErrInvalidToken            = `{"error":"invalid_token"}`
	JSONErrUserNotFound            = `{"error":"user_not_found"}`
)
