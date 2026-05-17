package main

import (
	"html/template"
	"net/http"
	"path/filepath"
	"strings"

	bettergoth "github.com/Protofarm/better-goth/better-goth"
	"github.com/Protofarm/better-goth/providers"
)

func registerExampleRoutes(router bettergoth.RouteRegistrar, runtime *bettergoth.Runtime) error {
	homeTemplate, dashboardTemplate, err := loadTemplates(filepath.Join(runtime.ConfigDir, "templates"))
	if err != nil {
		return err
	}

	bettergoth.RegisterRoutes(router, runtime.Auth)
	registerHelpRoute(router, runtime)
	registerHomeRoute(router, homeTemplate, runtime)
	router.Handle("GET /dashboard", handleDashboard(runtime.Auth, runtime.Store, dashboardTemplate, runtime.CookieName, runtime.CookieSecure))
	router.HandleFunc("POST /signout", bettergoth.SignOutHandler(runtime.CookieName, runtime.CookieSecure, "/"))
	router.Handle("GET /api/resource", bettergoth.NewSessionResourceHandler(runtime.Auth, runtime.CookieName, "/"))
	router.HandleFunc("GET /api/resource/bearer", bettergoth.NewBearerResourceHandler(runtime.Auth))
	router.HandleFunc("GET /v1/tokens", bettergoth.NewTokensListHandler(runtime.Store))
	router.HandleFunc("GET /v1/tokens/{sessionID}", bettergoth.NewTokenGetHandler(runtime.Store))
	router.HandleFunc("POST /v1/tokens/store", bettergoth.NewTokenStoreHandler(runtime.Store))
	router.HandleFunc("PUT /v1/tokens/{sessionID}", bettergoth.NewTokenUpdateHandler(runtime.Store))
	return nil
}

func registerHelpRoute(router bettergoth.RouteRegistrar, runtime *bettergoth.Runtime) {
	router.HandleFunc("GET /help", func(w http.ResponseWriter, r *http.Request) {
		help := map[string]interface{}{
			"rdapConformance": []string{"rdapLevel0", "farv1"},
			"notices": []map[string]interface{}{
				{
					"title": "Authentication Required",
					"description": []string{
						"This RDAP server supports authentication via OpenID Connect.",
						"Use /login/oauthserver to initiate authentication.",
					},
				},
			},
			"supportedOPs": []map[string]interface{}{
				{
					"issuer":    strings.TrimRight(runtime.OAuthIssuer, "/"),
					"client_id": runtime.OAuthClientID,
					"scopes":    []string{"openid", "profile", "email"},
				},
			},
		}
		bettergoth.WriteJSON(w, http.StatusOK, help)
	})
}

func registerHomeRoute(router bettergoth.RouteRegistrar, homeTemplate *template.Template, runtime *bettergoth.Runtime) {
	providerLoginPath := "/login/" + providers.OAuthServerProviderName
	googleLoginPath := ""
	if runtime.Auth != nil {
		if _, ok := runtime.Auth.Providers["google"]; ok {
			googleLoginPath = "/login/google"
		}
	}
	signupURL := strings.TrimRight(runtime.OAuthIssuer, "/") + "/signup"

	router.HandleFunc("GET /{$}", handleHome(homeTemplate, providerLoginPath, googleLoginPath, signupURL))
}

func loadTemplates(templateDir string) (home *template.Template, dashboard *template.Template, err error) {
	if strings.TrimSpace(templateDir) == "" {
		templateDir = "templates"
	}

	homePath := filepath.Join(templateDir, "home.html")
	dashboardPath := filepath.Join(templateDir, "dashboard.html")

	home, err = template.ParseFiles(homePath)
	if err != nil {
		return nil, nil, err
	}

	dashboard, err = template.ParseFiles(dashboardPath)
	if err != nil {
		return nil, nil, err
	}

	return home, dashboard, nil
}
