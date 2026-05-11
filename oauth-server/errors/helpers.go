package errors

import "strings"

// ValidateErrorCode checks if an error code is valid according to OAuth 2.0 specifications
func ValidateErrorCode(errCode string) bool {
	validCodes := map[string]bool{
		CodeInvalidRequest:         true,
		CodeInvalidClient:          true,
		CodeInvalidGrant:           true,
		CodeUnauthorizedClient:     true,
		CodeUnsupportedGrantType:   true,
		CodeUnsupportedResponseType: true,
		CodeInvalidScope:           true,
		CodeServerError:            true,
		CodeTemporarilyUnavailable: true,
		CodeInvalidRedirectURI:     true,
		CodeMethodNotAllowed:       true,
		CodeMissingToken:           true,
		CodeInvalidToken:           true,
		CodeInsufficientScope:      true,
		CodeUnauthorized:           true,
		CodeUserNotFound:           true,
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
		CodeServerError:            true,
		CodeTemporarilyUnavailable: true,
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
		return CodeInvalidGrant, "The provided credentials are invalid"
	case strings.Contains(storeErr, "user not found"):
		return CodeInvalidGrant, "The user does not exist"
	case strings.Contains(storeErr, "client not found"):
		return CodeInvalidClient, "The client does not exist"
	case strings.Contains(storeErr, "code not found"):
		return CodeInvalidGrant, "The authorization code is invalid"
	case strings.Contains(storeErr, "access token not found"):
		return CodeInvalidToken, "The access token is invalid"
	case strings.Contains(storeErr, "refresh token not found"):
		return CodeInvalidGrant, "The refresh token is invalid"
	case strings.Contains(storeErr, "username already exists"):
		return CodeInvalidRequest, "The username is already in use"
	case strings.Contains(storeErr, "email already registered"):
		return CodeInvalidRequest, "The email is already registered"
	case strings.Contains(storeErr, "unable to create user"):
		return CodeServerError, "Failed to create user"
	default:
		return CodeServerError, "An error occurred"
	}
}
