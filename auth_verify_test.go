package bettergoth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestAuth(t *testing.T) *Auth {
	t.Helper()

	auth, err := NewAuth([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf("NewAuth() error = %v", err)
	}

	return auth
}

func TestVerifyToken(t *testing.T) {
	auth := newTestAuth(t)

	validToken, err := auth.signJWT("user-123", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signJWT() error = %v", err)
	}

	wrongSecretAuth, err := NewAuth([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	if err != nil {
		t.Fatalf("NewAuth() with alternate secret error = %v", err)
	}

	wrongSecretToken, err := wrongSecretAuth.signJWT("user-123", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signJWT() with alternate secret error = %v", err)
	}

	wrongAlgToken, err := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.RegisteredClaims{
		Subject:   "user-123",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(auth.jwtSecret)
	if err != nil {
		t.Fatalf("SignedString() with HS384 error = %v", err)
	}

	expiredToken, err := auth.signJWT("user-123", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("signJWT() expired token error = %v", err)
	}

	missingSubjectToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(auth.jwtSecret)
	if err != nil {
		t.Fatalf("SignedString() missing subject error = %v", err)
	}

	tests := []struct {
		name      string
		token     string
		wantSub   string
		wantError error
	}{
		{
			name:    "valid token",
			token:   validToken,
			wantSub: "user-123",
		},
		{
			name:      "empty token",
			token:     "",
			wantError: ErrInvalidToken,
		},
		{
			name:      "wrong secret",
			token:     wrongSecretToken,
			wantError: ErrInvalidToken,
		},
		{
			name:      "wrong signing algorithm",
			token:     wrongAlgToken,
			wantError: ErrInvalidToken,
		},
		{
			name:      "expired token",
			token:     expiredToken,
			wantError: ErrInvalidToken,
		},
		{
			name:      "missing subject",
			token:     missingSubjectToken,
			wantError: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := auth.VerifyToken(tt.token)
			if tt.wantError != nil {
				if !errors.Is(err, tt.wantError) {
					t.Fatalf("VerifyToken() error = %v, want %v", err, tt.wantError)
				}
				if user != nil {
					t.Fatalf("VerifyToken() user = %#v, want nil", user)
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyToken() error = %v", err)
			}
			if user == nil {
				t.Fatal("VerifyToken() user = nil, want non-nil")
			}
			if user.Subject != tt.wantSub {
				t.Fatalf("VerifyToken() subject = %q, want %q", user.Subject, tt.wantSub)
			}
			if user.Claims.Subject != tt.wantSub {
				t.Fatalf("VerifyToken() claims subject = %q, want %q", user.Claims.Subject, tt.wantSub)
			}
			if user.Token != tt.token {
				t.Fatalf("VerifyToken() token = %q, want original token", user.Token)
			}
		})
	}
}

func TestVerifyRequest(t *testing.T) {
	auth := newTestAuth(t)

	validToken, err := auth.signJWT("user-123", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signJWT() error = %v", err)
	}

	tests := []struct {
		name      string
		header    string
		wantSub   string
		wantError error
	}{
		{
			name:    "valid bearer token",
			header:  "Bearer " + validToken,
			wantSub: "user-123",
		},
		{
			name:      "missing authorization header",
			wantError: ErrMissingAuthHeader,
		},
		{
			name:      "wrong scheme",
			header:    "Basic " + validToken,
			wantError: ErrInvalidAuthHeader,
		},
		{
			name:      "missing token",
			header:    "Bearer",
			wantError: ErrInvalidAuthHeader,
		},
		{
			name:    "extra whitespace",
			header:  "   Bearer   " + validToken + "   ",
			wantSub: "user-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			user, err := auth.VerifyRequest(req)
			if tt.wantError != nil {
				if !errors.Is(err, tt.wantError) {
					t.Fatalf("VerifyRequest() error = %v, want %v", err, tt.wantError)
				}
				if user != nil {
					t.Fatalf("VerifyRequest() user = %#v, want nil", user)
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyRequest() error = %v", err)
			}
			if user == nil {
				t.Fatal("VerifyRequest() user = nil, want non-nil")
			}
			if user.Subject != tt.wantSub {
				t.Fatalf("VerifyRequest() subject = %q, want %q", user.Subject, tt.wantSub)
			}
		})
	}
}

func TestRequireAuth(t *testing.T) {
	auth := newTestAuth(t)

	validToken, err := auth.signJWT("user-123", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("signJWT() error = %v", err)
	}

	tests := []struct {
		name       string
		header     string
		wantStatus int
		wantBody   string
		wantCalled bool
	}{
		{
			name:       "valid bearer token",
			header:     "Bearer " + validToken,
			wantStatus: http.StatusOK,
			wantBody:   "user-123",
			wantCalled: true,
		},
		{
			name:       "invalid token",
			header:     "Bearer invalid-token",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "unauthorized\n",
			wantCalled: false,
		},
		{
			name:       "missing header",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "unauthorized\n",
			wantCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true

				user, ok := UserFromContext(r.Context())
				if !ok {
					t.Fatal("UserFromContext() ok = false, want true")
				}

				_, _ = w.Write([]byte(user.Subject))
			}))

			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("RequireAuth() status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if strings.TrimSpace(rr.Body.String()) != strings.TrimSpace(tt.wantBody) {
				t.Fatalf("RequireAuth() body = %q, want %q", rr.Body.String(), tt.wantBody)
			}
			if called != tt.wantCalled {
				t.Fatalf("RequireAuth() called next = %v, want %v", called, tt.wantCalled)
			}
		})
	}
}
