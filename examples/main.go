package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	bettergoth "github.com/Protofarm/better-goth"
	"github.com/Protofarm/better-goth/pb"
	"github.com/Protofarm/better-goth/providers"
	"github.com/joho/godotenv"
)

const (
	jwtCookieName = "session_id"
)

// jwt over http only secure
var jwtCookieSecure = true

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

func main() {
	mux := http.NewServeMux()

	if err := godotenv.Load(); err != nil {
		log.Println("No .env loaded, using environment variables as-is")
	}

	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	jwtSecret := os.Getenv("JWT_SECRET")

	homeTemplate, dashboardTemplate, err := loadTemplates()
	if err != nil {
		log.Fatalf("failed to load templates: %v", err)
	}

	google, err := providers.NewGoogleProvider(
		clientID,
		clientSecret,
		"http://localhost:8080/callback/google",
		[]string{},
	)
	if err != nil {
		log.Fatal(err)
	}

	auth, err := bettergoth.NewAuth([]byte(jwtSecret))
	if err != nil {
		log.Fatal(err)
	}

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

	auth.AddProvider(google)
	bettergoth.RegisterRoutes(mux, auth)

	// Home page (app-owned)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if err := homeTemplate.Execute(w, nil); err != nil {
			http.Error(w, "failed to render home page", http.StatusInternalServerError)
			return
		}
	})

	// Dashboard (app-owned, protected)
	mux.Handle("GET /dashboard", authFromCookie(auth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			CookieSecure: jwtCookieSecure,
			Routes: []routeInfo{
				{
					Method:      "GET",
					Path:        "/login/{provider}",
					Owner:       "Library (better-goth)",
					Description: "Starts OAuth flow and redirects to provider",
				},
				{
					Method:      "GET",
					Path:        "/callback/{provider}",
					Owner:       "Library + App hook",
					Description: "Library validates OAuth callback, builds auth result, invokes app handler",
				},
				{
					Method:      "GET",
					Path:        "/",
					Owner:       "App",
					Description: "Homepage with login action",
				},
				{
					Method:      "GET",
					Path:        "/dashboard",
					Owner:       "App",
					Description: "Protected dashboard showing route ownership and user details",
				},
				{
					Method:      "GET",
					Path:        "/api/resource",
					Owner:       "App",
					Description: "Protected resource endpoint using session cookie auth",
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
			},
		}

		if err := dashboardTemplate.Execute(w, data); err != nil {
			http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
			return
		}
	})))

	mux.Handle("GET /api/resource", authFromCookie(auth, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := bettergoth.UserFromContext(r.Context())
		if !ok {
			http.Error(w, "missing user from context", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"sub":     user.Subject,
			"message": "protected resource access granted",
		})
	})))

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

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
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
