package main

import (
	"html/template"
	"net/http"
	"strings"
)

type authPageData struct {
	// FormAction is the full URL (including query string) the sign-in/sign-up forms POST to.
	// It points at the OAuth server's /authorize endpoint so credentials are validated there.
	FormAction  string
	OAuthIssuer string
}

// handleAuthorize serves the sign-in/sign-up page for the built-in OAuth server.
//
// The OAuth server no longer renders HTML (it is API-only). main.go overrides the
// oauthserver provider's authorization URL to this local route so the library's
// redirect lands here instead of directly on port 8080.
//
// The rendered forms POST back to the OAuth server with the original OIDC query
// params preserved in the action URL.
func handleAuthorize(oauthIssuer string, tmpl *template.Template) func(http.ResponseWriter, *http.Request) {
	issuer := strings.TrimRight(oauthIssuer, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		rawQuery := r.URL.RawQuery
		formAction := issuer + "/authorize"
		if rawQuery != "" {
			formAction += "?" + rawQuery
		}

		data := authPageData{
			FormAction:  formAction,
			OAuthIssuer: issuer,
		}
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "failed to render authorize page", http.StatusInternalServerError)
		}
	}
}
