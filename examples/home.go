package main

import (
	"html/template"
	"net/http"
)

type providerOption struct {
	Name      string
	LoginPath string
	Label     string
}

type homeData struct {
	OAuthServerLoginPath string
	OAuthServerEnabled   bool
	ExternalProviders    []providerOption
}

func handleHome(tmpl *template.Template, data homeData) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "failed to render home page", http.StatusInternalServerError)
		}
	}
}
