package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Protofarm/better-goth/oauth-server/store"
)

func TestAuthorizeHandler_PKCEEnforcement(t *testing.T) {
	s := store.NewStore(store.Config{
		DefaultClientID:     "test-client",
		DefaultClientSecret: "test-secret",
		DefaultRedirectURIs: []string{"http://localhost/callback"},
	})
	handler := AuthorizeHandler(s)

	tests := []struct {
		name           string
		queryParams    url.Values
		expectedStatus int
	}{
		{
			name: "Missing code_challenge",
			queryParams: url.Values{
				"response_type": {"code"},
				"client_id":     {"test-client"},
				"redirect_uri":  {"http://localhost/callback"},
				"state":         {"xyz"},
			},
			expectedStatus: http.StatusFound, // Redirects with error
		},
		{
			name: "Wrong code_challenge_method",
			queryParams: url.Values{
				"response_type":          {"code"},
				"client_id":              {"test-client"},
				"redirect_uri":           {"http://localhost/callback"},
				"state":                  {"xyz"},
				"code_challenge":         {"challenge"},
				"code_challenge_method": {"plain"},
			},
			expectedStatus: http.StatusFound, // Redirects with error
		},
		{
			name: "Valid PKCE",
			queryParams: url.Values{
				"response_type":          {"code"},
				"client_id":              {"test-client"},
				"redirect_uri":           {"http://localhost/callback"},
				"state":                  {"xyz"},
				"code_challenge":         {"challenge"},
				"code_challenge_method": {"S256"},
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/authorize?"+tt.queryParams.Encode(), nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedStatus == http.StatusFound {
				location, _ := url.Parse(rr.Header().Get("Location"))
				if location.Query().Get("error") == "" {
					t.Error("expected error parameter in redirect")
				}
			}
		})
	}
}
