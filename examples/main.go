package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	bettergoth "github.com/Protofarm/better-goth"
	oauthserver "github.com/Protofarm/better-goth/oauth-server"
	"github.com/Protofarm/better-goth/pb"
	"github.com/Protofarm/better-goth/providers"
	"github.com/joho/godotenv"
)

const (
	jwtCookieName = "session_id"
)

// jwt over http only secure
var jwtCookieSecure = false

func envOrDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envBoolOrDefault(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}

	return parsed
}

func normalizePort(port string) string {
	p := strings.TrimSpace(port)
	p = strings.TrimPrefix(p, ":")
	if p == "" {
		return "3000"
	}
	return p
}

type tokenRecord struct {
	Provider     string `json:"provider"`
	UserSub      string `json:"user_sub"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	SignedJWT    string `json:"signed_jwt"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
}

type tokenStore struct {
	mu   sync.RWMutex
	data map[string]tokenRecord
}

func newTokenStore() *tokenStore {
	return &tokenStore{
		data: make(map[string]tokenRecord),
	}
}

func (s *tokenStore) save(record tokenRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[record.UserSub] = record
}

func (s *tokenStore) getBySub(sub string) (tokenRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[sub]
	return v, ok
}

func (s *tokenStore) all() map[string]tokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]tokenRecord, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}



func loadTemplates() (home *template.Template, dashboard *template.Template, err error) {
	homePath := filepath.Join("templates", "home.html")
	dashboardPath := filepath.Join("templates", "dashboard.html")

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

func splitCSV(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func rotateOAuthServerKey(ctx context.Context, issuerURL string) (int, []byte, error) {
	rotateURL := strings.TrimRight(issuerURL, "/") + "/admin/rotate"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rotateURL, nil)
	if err != nil {
		return 0, nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	return resp.StatusCode, body, nil
}

func main() {
	mux := http.NewServeMux()

	if err := godotenv.Load(); err != nil {
		log.Println("No .env loaded, using environment variables as-is")
	}

	devMode := envBoolOrDefault("DEV_MODE", false)

	appPort := normalizePort(envOrDefault("APP_PORT", "3000"))
	appScheme := "http"
	oauthScheme := "http"
	if !devMode {
		appScheme = "https"
		oauthScheme = "https"
	}

	oauthServerIssuer := envOrDefault("OAUTH_SERVER_ISSUER_URL", fmt.Sprintf("%s://localhost:8080", oauthScheme))
	oauthServerClientID := envOrDefault("OAUTH_SERVER_CLIENT_ID", "my-client")
	oauthServerClientSecret := envOrDefault("OAUTH_SERVER_CLIENT_SECRET", "my-secret")
	googleClientID := envOrDefault("GOOGLE_CLIENT_ID", "")
	googleClientSecret := envOrDefault("GOOGLE_CLIENT_SECRET", "")
	jwtSecret := envOrDefault("JWT_SECRET", "replace-with-at-least-32-bytes-secret")
	jwtCookieSecure = !devMode

	oauthPort := normalizePort(envOrDefault("OAUTH_SERVER_PORT", "8080"))
	keyDir := envOrDefault("OAUTH_SERVER_KEY_DIR", "keys")
	defaultRedirectURI := fmt.Sprintf("%s://localhost:%s/callback/oauthserver", appScheme, appPort)
	redirectURIs := splitCSV(envOrDefault("OAUTH_SERVER_REDIRECT_URIS", defaultRedirectURI))

	tlsCert := envOrDefault("OAUTH_SERVER_TLS_CERT", "")
	tlsKey := envOrDefault("OAUTH_SERVER_TLS_KEY", "")

	// use default oauth server implementation, can be managed automatically
	oauthServer, err := oauthserver.CreateOAuthServer(oauthPort, oauthServerIssuer, keyDir, oauthServerClientID, oauthServerClientSecret, redirectURIs, devMode)
	go func() {
		listenAddr := ":" + oauthPort
		log.Printf("OAuth 2.0 server listening on %s", listenAddr)
		if devMode || tlsCert == "" || tlsKey == "" {
			log.Fatal(http.ListenAndServe(listenAddr, oauthServer))
		} else {
			log.Fatal(http.ListenAndServeTLS(listenAddr, tlsCert, tlsKey, oauthServer))
		}
	}()

	providerLoginPath := "/login/" + providers.OAuthServerProviderName
	googleLoginPath := "/login/google"
	signupURL := strings.TrimRight(oauthServerIssuer, "/") + "/signup"

	homeTemplate, dashboardTemplate, err := loadTemplates()
	if err != nil {
		log.Fatalf("failed to load templates: %v", err)
	}

	oauthServerProvider, err := providers.NewOAuthServerProvider(
		oauthServerIssuer,
		oauthServerClientID,
		oauthServerClientSecret,
		fmt.Sprintf("%s://localhost:%s/callback/%s", appScheme, appPort, providers.OAuthServerProviderName),
		[]string{},
	)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := bettergoth.NewAuth([]byte(jwtSecret))
	if err != nil {
		log.Fatal(err)
	}
	auth.SetDevMode(devMode)

	store := newTokenStore()

	auth.SetUserHandler(bettergoth.UserHandlerFunc(func(ctx context.Context, user *pb.User) error {
		log.Printf("authenticated user: sub=%s email=%s", user.GetSub(), user.GetEmail())
		return nil
	}))

	// Library callback -> app-controlled behavior.
	auth.SetAuthResultHandler(bettergoth.AuthResultHandlerFunc(
		func(ctx context.Context, w http.ResponseWriter, r *http.Request, result *bettergoth.AuthResult) error {
			record := tokenRecord{
				Provider:     result.Provider,
				UserSub:      result.User.GetSub(),
				Email:        result.User.GetEmail(),
				Name:         result.User.GetName(),
				SignedJWT:    result.SignedToken,
				AccessToken:  result.AccessToken,
				RefreshToken: result.RefreshToken,
				TokenType:    result.TokenType,
				ExpiresAt:    result.ExpiresAt.UTC().Format(time.RFC3339),
			}

			// Async app-owned persistence step.
			go store.save(record)

			// App chooses to share JWT via HttpOnly cookie and redirect.
			http.SetCookie(w, &http.Cookie{
				Name:     jwtCookieName,
				Value:    result.SignedToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   jwtCookieSecure,
				SameSite: http.SameSiteLaxMode,
				Expires:  result.ExpiresAt,
			})

			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return nil
		},
	))

	auth.AddProvider(oauthServerProvider)

	// Add Google provider if credentials are provided
	if googleClientID != "" && googleClientSecret != "" {
		googleProvider, err := providers.NewGoogleProvider(
			googleClientID,
			googleClientSecret,
			fmt.Sprintf("%s://localhost:%s/callback/google", appScheme, appPort),
			[]string{},
		)
		if err != nil {
			log.Printf("Warning: failed to create Google provider: %v", err)
		} else {
			auth.AddProvider(googleProvider)
			log.Printf("Google provider registered")
		}
	}
	bettergoth.RegisterRoutes(mux, auth)

	mux.Handle("POST /admin/rotate", authFromCookie(auth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body, err := rotateOAuthServerKey(r.Context(), oauthServerIssuer)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to rotate oauth-server key: %v", err), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})))

	// RFC 9650: RDAP Help endpoint - advertise authentication support
	mux.HandleFunc("GET /help", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
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
					"issuer":    strings.TrimRight(oauthServerIssuer, "/"),
					"client_id": oauthServerClientID,
					"scopes":    []string{"openid", "profile", "email"},
				},
			},
		}
		json.NewEncoder(w).Encode(help)
	})

	// Home page (app-owned)
	mux.HandleFunc("GET /{$}", handleHome(homeTemplate, providerLoginPath, googleLoginPath, signupURL))

	// Dashboard (app-owned, protected)
	mux.Handle("GET /dashboard", handleDashboard(auth, store, dashboardTemplate, jwtCookieSecure))

	mux.Handle("GET /api/resource", handleAPIResource(auth))

	// RFC 6750: Bearer token endpoint - protected resource with Bearer token auth
	mux.HandleFunc("GET /api/resource/bearer", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.VerifyRequest(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token" error_description="Authorization header must contain a valid Bearer token"`)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_token",
				"error_description": "Authorization header must contain a valid Bearer token",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sub":            user.Subject,
			"message":        "protected resource access granted",
			"authentication": "Bearer token",
		})
	})

	mux.HandleFunc("POST /signout", func(w http.ResponseWriter, r *http.Request) {
		clearAuthCookie(w)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// JSON routes
	mux.HandleFunc("GET /v1/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(store.all())
	})

	mux.HandleFunc("GET /v1/tokens/{sessionID}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		if sessionID == "" {
			http.Error(w, "missing sessionID path param", http.StatusBadRequest)
			return
		}

		rec, ok := store.getBySub(sessionID)
		if !ok {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(rec)
	})

	mux.HandleFunc("POST /v1/tokens/store", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var rec tokenRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if rec.UserSub == "" {
			http.Error(w, "missing user_sub", http.StatusBadRequest)
			return
		}

		store.save(rec)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(rec)
	})

	mux.HandleFunc("PUT /v1/tokens/{sessionID}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("sessionID")
		if sessionID == "" {
			http.Error(w, "missing sessionID path param", http.StatusBadRequest)
			return
		}

		defer r.Body.Close()

		var rec tokenRecord
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if rec.UserSub == "" {
			rec.UserSub = sessionID
		}
		if rec.UserSub != sessionID {
			http.Error(w, "sessionID path does not match payload user_sub", http.StatusBadRequest)
			return
		}

		store.save(rec)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(rec)
	})

	listenAddr := ":" + appPort
	log.Printf("Server running on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   jwtCookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

// authFromCookie adapts cookie JWT into Authorization header so existing library auth middleware can be reused.
func authFromCookie(auth *bettergoth.Auth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(jwtCookieName)
		if err != nil || c == nil || c.Value == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		cloned := r.Clone(r.Context())
		cloned.Header.Set("Authorization", "Bearer "+c.Value)

		auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Keep URL tidy if someone arrives with auth artifacts.
			if req.URL.RawQuery != "" {
				if values, parseErr := url.ParseQuery(req.URL.RawQuery); parseErr == nil {
					values.Del("code")
					values.Del("state")
					req.URL.RawQuery = values.Encode()
				}
			}
			next.ServeHTTP(w, req)
		})).ServeHTTP(w, cloned)
	})
}
