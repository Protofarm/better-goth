package main

import (
	"html/template"
	"net/http"

	bettergoth "github.com/Protofarm/better-goth/better-goth"
)

const (
	appOwner                    = "App"
	appRouteLibraryHandlerOwner = "App route -> library handler"
	appRouteWithHookOwner       = "App route -> library handler + app hook"
)

type routeInfo struct {
	Method      string
	Path        string
	Owner       string
	Description string
}

type dashboardData struct {
	User         *bettergoth.VerifiedUser
	UserDetails  *bettergoth.TokenRecord
	AccessToken  string
	Routes       []routeInfo
	CookieSecure bool
}

func route(method, path, owner, description string) routeInfo {
	return routeInfo{
		Method:      method,
		Path:        path,
		Owner:       owner,
		Description: description,
	}
}

func dashboardRoutes() []routeInfo {
	return []routeInfo{
		route("GET", "/help", appOwner, "RFC 9650 RDAP help endpoint - advertises authentication capabilities with 'farv1' support"),
		route("GET", "/", appOwner, "Homepage with login options"),
		route("GET", "/login/oauthserver", appRouteLibraryHandlerOwner, "Starts OAuth 2.0 authorization code flow against the configured provider"),
		route("GET", "/callback/oauthserver", appRouteWithHookOwner, "OAuth callback - better-goth validates tokens and the app handles the result hook"),
		route("GET", "/dashboard", appOwner, "Protected dashboard showing route ownership and user details (session cookie auth)"),
		route("GET", "/api/resource", appRouteLibraryHandlerOwner, "Protected resource endpoint using session cookie authentication (RFC 6750 via cookie)"),
		route("GET", "/api/resource/bearer", appRouteLibraryHandlerOwner, "Protected resource endpoint using Bearer token (RFC 6750) from Authorization header"),
		route("POST", "/signout", appRouteLibraryHandlerOwner, "Clears the JWT cookie and redirects to the homepage"),
		route("POST", "/v1/tokens/store", appRouteLibraryHandlerOwner, "Stores a token record in the better-goth in-memory token store"),
		route("GET", "/v1/tokens", appRouteLibraryHandlerOwner, "Returns all in-memory token records as JSON"),
		route("GET", "/v1/tokens/{sessionID}", appRouteLibraryHandlerOwner, "Returns one in-memory token record by sessionID as JSON"),
		route("PUT", "/v1/tokens/{sessionID}", appRouteLibraryHandlerOwner, "Updates one in-memory token record by sessionID"),
	}
}

func handleDashboard(auth *bettergoth.Auth, store *bettergoth.TokenStore, dashboardTemplate *template.Template, cookieName string, cookieSecure bool) http.Handler {
	return bettergoth.AuthFromCookie(auth, cookieName, "/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := bettergoth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		var details *bettergoth.TokenRecord
		var accessToken string
		if rec, found := store.Get(user.Subject); found {
			details = &rec
			accessToken = rec.AccessToken
		}

		data := dashboardData{
			User:         user,
			UserDetails:  details,
			AccessToken:  accessToken,
			CookieSecure: cookieSecure,
			Routes:       dashboardRoutes(),
		}

		if err := dashboardTemplate.Execute(w, data); err != nil {
			http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
			return
		}
	}))
}
