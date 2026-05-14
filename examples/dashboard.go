package main

import (
	"encoding/json"
	"html/template"
	"net/http"

	bettergoth "github.com/Protofarm/better-goth"
)

type routeInfo struct {
	Method      string
	Path        string
	Owner       string
	Description string
}

type dashboardData struct {
	User         *bettergoth.VerifiedUser
	UserDetails  *tokenRecord
	Routes       []routeInfo
	CookieSecure bool
}

func dashboardRoutes() []routeInfo {
	return []routeInfo{
		{
			Method:      "GET",
			Path:        "/help",
			Owner:       "App",
			Description: "RFC 9650 RDAP help endpoint - advertises authentication capabilities with 'farv1' support",
		},
		{
			Method:      "GET",
			Path:        "/",
			Owner:       "App",
			Description: "Homepage with login options",
		},
		{
			Method:      "GET",
			Path:        "/login/oauthserver",
			Owner:       "Library (better-goth)",
			Description: "Starts OAuth 2.0 authorization code flow against local oauth-server",
		},
		{
			Method:      "GET",
			Path:        "/callback/oauthserver",
			Owner:       "Library + App hook",
			Description: "OAuth callback - library validates, app handles result via AuthResultHandler",
		},
		{
			Method:      "GET",
			Path:        "/dashboard",
			Owner:       "App",
			Description: "Protected dashboard showing route ownership and user details (session cookie auth)",
		},
		{
			Method:      "POST",
			Path:        "/admin/rotate",
			Owner:       "App",
			Description: "Triggers oauth-server RSA key rotation through the protected app",
		},
		{
			Method:      "GET",
			Path:        "/api/resource",
			Owner:       "App",
			Description: "Protected resource endpoint using session cookie authentication (RFC 6750 via cookie)",
		},
		{
			Method:      "GET",
			Path:        "/api/resource/bearer",
			Owner:       "App",
			Description: "Protected resource endpoint using Bearer token (RFC 6750) from Authorization header",
		},
		{
			Method:      "POST",
			Path:        "/signout",
			Owner:       "App",
			Description: "Clears the JWT cookie and redirects to the homepage",
		},
		{
			Method:      "POST",
			Path:        "/v1/tokens/store",
			Owner:       "App",
			Description: "Stores a token record in the in-memory token store",
		},
		{
			Method:      "GET",
			Path:        "/v1/tokens",
			Owner:       "App",
			Description: "Returns all in-memory token records as JSON",
		},
		{
			Method:      "GET",
			Path:        "/v1/tokens/{sessionID}",
			Owner:       "App",
			Description: "Returns one in-memory token record by sessionID as JSON",
		},
		{
			Method:      "PUT",
			Path:        "/v1/tokens/{sessionID}",
			Owner:       "App",
			Description: "Updates one in-memory token record by sessionID",
		},
	}
}

func handleDashboard(auth *bettergoth.Auth, store *tokenStore, dashboardTemplate any, cookieSecure bool) http.Handler {
	return authFromCookie(auth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := bettergoth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		var details *tokenRecord
		if rec, found := store.getBySub(user.Subject); found {
			details = &rec
		}

		data := dashboardData{
			User:         user,
			UserDetails:  details,
			CookieSecure: cookieSecure,
			Routes:       dashboardRoutes(),
		}

		tmpl := dashboardTemplate.(*template.Template)
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
			return
		}
	}))
}

func handleAPIResource(auth *bettergoth.Auth) http.Handler {
	return authFromCookie(auth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := bettergoth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            user.Subject,
			"message":        "protected resource access granted",
			"authentication": "session cookie",
		})
	}))
}
