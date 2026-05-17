package errors

// OAuth 2.0 Error Codes (RFC 6749)
const (
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeInvalidScope            = "invalid_scope"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeServerError             = "server_error"
)

const (
	CodeMethodNotAllowed = "method_not_allowed"
)

const (
	CodeMissingToken = "missing_token"
	CodeInvalidToken = "invalid_token"
)
