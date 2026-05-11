package errors

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
