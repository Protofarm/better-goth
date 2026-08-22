package main

import (
	"html/template"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	bettergoth "github.com/Protofarm/better-goth"
	"github.com/Protofarm/better-goth/internal/providers"
)

type appTemplates struct {
	home      *template.Template
	auth      *template.Template
	dashboard *template.Template
}

func registerExampleRoutes(router bettergoth.RouteRegistrar, runtime *bettergoth.Runtime) error {
	tmpl, err := loadTemplates(filepath.Join(runtime.ConfigDir, "templates"))
	if err != nil {
		return err
	}

	authMW := func(next http.Handler) http.Handler {
		return bettergoth.AuthFromCookie(runtime.Auth, runtime.CookieName, "/", next)
	}

	bettergoth.RegisterRoutes(router, runtime.Auth)
	registerHelpRoute(router, runtime)
	registerHomeRoute(router, tmpl.home, runtime)

	// The example app serves the OAuth sign-in/sign-up page locally.
	// main.go overrides the oauthserver provider's auth URL to point here.
	// The rendered form POSTs credentials to the OAuth server's /authorize.
	router.HandleFunc("GET /authorize", handleAuthorize(runtime.OAuthIssuer, tmpl.auth))

	router.Handle("GET /dashboard", authMW(handleDashboard(runtime, tmpl.dashboard)))

	// Client management — all server-rendered, no JS required.
	router.Handle("POST /dashboard/client", authMW(handleClientCreate(runtime.Store, runtime.OAuthIssuer)))
	router.Handle("POST /dashboard/client/regenerate", authMW(handleClientRegenerate(runtime.Store, runtime.OAuthIssuer)))
	router.Handle("POST /dashboard/client/update", authMW(handleClientUpdate(runtime.Store, runtime.OAuthIssuer)))
	router.Handle("POST /dashboard/client/delete", authMW(handleClientDelete(runtime.Store, runtime.OAuthIssuer)))

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
					"title": "Authentication",
					"description": []string{
						"Use /login/oauthserver to start the OAuth 2.0 authorization code flow.",
						"Append ?client_id=...&client_secret=... to use custom credentials.",
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
	router.HandleFunc("GET /{$}", handleHome(homeTemplate, buildHomeData(runtime)))
}

func buildHomeData(runtime *bettergoth.Runtime) homeData {
	_, oauthEnabled := runtime.Auth.Providers[providers.OAuthServerProviderName]

	var external []providerOption
	for name := range runtime.Auth.Providers {
		if name == providers.OAuthServerProviderName {
			continue
		}
		external = append(external, providerOption{
			Name:      name,
			LoginPath: "/login/" + name,
			Label:     providerLabel(name),
		})
	}
	sort.Slice(external, func(i, j int) bool { return external[i].Name < external[j].Name })

	return homeData{
		OAuthServerLoginPath: "/login/" + providers.OAuthServerProviderName,
		OAuthServerEnabled:   oauthEnabled,
		ExternalProviders:    external,
	}
}

func providerLabel(name string) string {
	switch strings.ToLower(name) {
	case "google":
		return "Google"
	case "github":
		return "GitHub"
	case "microsoft":
		return "Microsoft"
	case "facebook":
		return "Facebook"
	case "apple":
		return "Apple"
	default:
		if len(name) == 0 {
			return name
		}
		return strings.ToUpper(name[:1]) + name[1:]
	}
}

func loadTemplates(templateDir string) (*appTemplates, error) {
	if strings.TrimSpace(templateDir) == "" {
		templateDir = "templates"
	}
	parse := func(name string) (*template.Template, error) {
		return template.ParseFiles(filepath.Join(templateDir, name))
	}

	home, err := parse("home.html")
	if err != nil {
		return nil, err
	}
	auth, err := parse("auth.html")
	if err != nil {
		return nil, err
	}
	dashboard, err := parse("dashboard.html")
	if err != nil {
		return nil, err
	}

	return &appTemplates{home: home, auth: auth, dashboard: dashboard}, nil
}
