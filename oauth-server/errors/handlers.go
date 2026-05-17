package errors

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

const (
	contentTypeHeader = "Content-Type"
	applicationJSON   = "application/json"
)

// TokenError writes an OAuth 2.0 error response for the token endpoint
// RFC 6749 Section 5.2: Error Response
func TokenError(w http.ResponseWriter, errCode, desc string) {
	OAuthError(w, http.StatusBadRequest, errCode, desc)
}

// InvalidClientError writes an OAuth client authentication error response.
func InvalidClientError(w http.ResponseWriter, desc string) {
	OAuthError(w, http.StatusUnauthorized, CodeInvalidClient, desc)
}

// OAuthError writes an OAuth 2.0 JSON error response.
func OAuthError(w http.ResponseWriter, status int, errCode, desc string) {
	w.Header().Set(contentTypeHeader, applicationJSON)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	}); err != nil {
		log.Printf("failed to write token error response: %v", err)
	}
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
	w.Header().Set(contentTypeHeader, applicationJSON)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s"`, errCode))
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, errCode, description); err != nil {
		log.Printf("failed to write OAuth error response: %v", err)
	}
}

// HTTPError writes a generic error response using JSON
// Used for endpoints like introspection, revocation, userinfo when they need to return JSON errors
func HTTPError(w http.ResponseWriter, errJSON string, status int) {
	w.Header().Set(contentTypeHeader, applicationJSON)
	w.WriteHeader(status)
	if _, err := w.Write([]byte(errJSON)); err != nil {
		log.Printf("failed to write HTTP error response: %v", err)
	}
}
