package main

import (
	"html/template"
	"net/http"
)

type homeData struct {
	OAuthServerLoginPath string
	GoogleLoginPath      string
	SignupURL            string
}

func handleHome(homeTemplate *template.Template, oauthServerLoginPath, googleLoginPath, signupURL string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := homeTemplate.Execute(w, homeData{
			OAuthServerLoginPath: oauthServerLoginPath,
			GoogleLoginPath:      googleLoginPath,
			SignupURL:            signupURL,
		}); err != nil {
			http.Error(w, "failed to render home page", http.StatusInternalServerError)
			return
		}
	}
}
