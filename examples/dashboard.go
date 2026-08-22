package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	bettergoth "github.com/Protofarm/better-goth"
)

const (
	ownerApp     = "App"
	ownerLibrary = "App route → library handler"
	ownerHook    = "App route → library handler + app hook"
)

type routeInfo struct {
	Method      string
	Path        string
	Owner       string
	Description string
}

// oauthClientInfo mirrors the OAuth server's client JSON response.
type oauthClientInfo struct {
	ID           string   `json:"id"`
	ClientSecret string   `json:"client_secret"`
	PublicKey    string   `json:"public_key"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	CreatedAt    string   `json:"created_at"`
}

type dashboardData struct {
	User         *bettergoth.VerifiedUser
	UserDetails  *bettergoth.TokenRecord
	Routes       []routeInfo
	CookieName   string
	CookieSecure bool
	Client       *oauthClientInfo
	ClientError  string
	Flash        string
	OAuthIssuer  string
}

func dashboardRoutes() []routeInfo {
	return []routeInfo{
		{"GET", "/help", ownerApp, "RDAP help — advertises supported authentication providers"},
		{"GET", "/", ownerApp, "Homepage — lists all configured login methods"},
		{"GET", "/authorize", ownerApp, "Serves the OAuth sign-in/sign-up form (posts credentials to OAuth server)"},
		{"GET", "/login/oauthserver", ownerLibrary, "Starts authorization code flow (default client)"},
		{"GET", "/login/oauthserver?client_id=…&client_secret=…", ownerLibrary, "Starts authorization code flow (custom client credentials)"},
		{"GET", "/login/{provider}", ownerLibrary, "Starts authorization code flow for any configured external provider"},
		{"GET", "/callback/{provider}", ownerHook, "OAuth callback — library validates token, app hook stores session and sets cookie"},
		{"GET", "/dashboard", ownerApp, "Protected dashboard (session cookie auth)"},
		{"POST", "/dashboard/client", ownerApp, "Create a new OAuth client for the authenticated user"},
		{"POST", "/dashboard/client/regenerate", ownerApp, "Regenerate the client secret"},
		{"POST", "/dashboard/client/update", ownerApp, "Update the client's public key endpoint"},
		{"POST", "/dashboard/client/delete", ownerApp, "Delete the client"},
		{"GET", "/api/resource", ownerLibrary, "Protected resource via session cookie (RFC 6750)"},
		{"GET", "/api/resource/bearer", ownerLibrary, "Protected resource via Bearer token (RFC 6750)"},
		{"POST", "/signout", ownerLibrary, "Clears session cookie and redirects to home"},
		{"GET", "/v1/tokens", ownerLibrary, "List all in-memory token records (JSON)"},
		{"GET", "/v1/tokens/{sessionID}", ownerLibrary, "Get one token record by user subject (JSON)"},
		{"POST", "/v1/tokens/store", ownerLibrary, "Manually store a token record"},
		{"PUT", "/v1/tokens/{sessionID}", ownerLibrary, "Update a token record"},
	}
}

func handleDashboard(runtime *bettergoth.Runtime, tmpl *template.Template) http.Handler {
	return bettergoth.AuthFromCookie(runtime.Auth, runtime.CookieName, "/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := bettergoth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user in context", http.StatusInternalServerError)
			return
		}

		var userDetails *bettergoth.TokenRecord
		if rec, found := runtime.Store.Get(user.Subject); found {
			userDetails = &rec
		}

		var client *oauthClientInfo
		var clientError string
		if userDetails != nil && userDetails.AccessToken != "" {
			var err error
			client, err = fetchClientInfo(userDetails.AccessToken, runtime.OAuthIssuer)
			if err != nil {
				clientError = fmt.Sprintf("could not load client info: %v", err)
			}
		}

		data := dashboardData{
			User:         user,
			UserDetails:  userDetails,
			Routes:       dashboardRoutes(),
			CookieName:   runtime.CookieName,
			CookieSecure: runtime.CookieSecure,
			Client:       client,
			ClientError:  clientError,
			Flash:        r.URL.Query().Get("flash"),
			OAuthIssuer:  strings.TrimRight(runtime.OAuthIssuer, "/"),
		}

		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
		}
	}))
}

func fetchClientInfo(accessToken, oauthIssuer string) (*oauthClientInfo, error) {
	issuer := strings.TrimRight(oauthIssuer, "/")
	req, err := http.NewRequest(http.MethodGet, issuer+"/oauth/client", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
		return nil, nil // no client registered yet
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OAuth server returned %d", resp.StatusCode)
	}

	var client oauthClientInfo
	if err := json.NewDecoder(resp.Body).Decode(&client); err != nil {
		return nil, err
	}
	return &client, nil
}
