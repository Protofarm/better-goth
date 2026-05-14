package main

import (
	"net/http"
	"net/url"
	"sync"

	bettergoth "github.com/Protofarm/better-goth"
)

const jwtCookieName = "session_id"

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
