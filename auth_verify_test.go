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

const (
	testUserID       = "user-123"
	signJWTErrorMsg  = "signJWT() error = %v"
	newAuthErrorMsg  = "NewAuth() error = %v"
	verifyTokenMsg   = "VerifyToken() error = %v"
	verifyRequestMsg = "VerifyRequest() error = %v"
)

func newTestAuth(t *testing.T) *Auth {
	t.Helper()

	auth, err := NewAuth([]byte("12345678901234567890123456789012"))
	if err != nil {
		t.Fatalf(newAuthErrorMsg, err)
	}

	return auth
}

func createValidToken(t *testing.T, auth *Auth) string {
	t.Helper()
	token, err := auth.signJWT(testUserID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf(signJWTErrorMsg, err)
	}
	return token
}

func createWrongSecretToken(t *testing.T) string {
	t.Helper()
	wrongSecretAuth, err := NewAuth([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	if err != nil {
		t.Fatalf(newAuthErrorMsg, err)
	}
	token, err := wrongSecretAuth.signJWT(testUserID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf(signJWTErrorMsg, err)
	}
	return token
}

func createWrongAlgToken(t *testing.T, auth *Auth) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.RegisteredClaims{
		Subject:   testUserID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(auth.jwtSecret)
	if err != nil {
		t.Fatalf("SignedString() with HS384 error = %v", err)
	}
	return token
}

func createExpiredToken(t *testing.T, auth *Auth) string {
	t.Helper()
	token, err := auth.signJWT(testUserID, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf(signJWTErrorMsg, err)
	}
	return token
}

func createMissingSubjectToken(t *testing.T, auth *Auth) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(auth.jwtSecret)
	if err != nil {
		t.Fatalf("SignedString() missing subject error = %v", err)
	}
	return token
}

func TestVerifyToken(t *testing.T) {
	auth := newTestAuth(t)

	validToken := createValidToken(t, auth)
	wrongSecretToken := createWrongSecretToken(t)
	wrongAlgToken := createWrongAlgToken(t, auth)
	expiredToken := createExpiredToken(t, auth)
	missingSubjectToken := createMissingSubjectToken(t, auth)

	tests := []struct {
		name      string
		token     string
		wantSub   string
		wantError error
	}{
		{
			name:    "valid token",
			token:   validToken,
			wantSub: testUserID,
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
			verifyTokenTestCase(t, auth, tt)
		})
	}
}

func verifyTokenTestCase(t *testing.T, auth *Auth, tt struct {
	name      string
	token     string
	wantSub   string
	wantError error
}) {
	user, err := auth.VerifyToken(tt.token)
	
	if tt.wantError != nil {
		if !errors.Is(err, tt.wantError) {
			t.Fatalf(verifyTokenMsg, err)
		}
		if user != nil {
			t.Fatalf("VerifyToken() user = %#v, want nil", user)
		}
		return
	}

	if err != nil {
		t.Fatalf(verifyTokenMsg, err)
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
}

func TestVerifyRequest(t *testing.T) {
	auth := newTestAuth(t)
	validToken := createValidToken(t, auth)

	tests := []struct {
		name      string
		header    string
		wantSub   string
		wantError error
	}{
		{
			name:    "valid bearer token",
			header:  "Bearer " + validToken,
			wantSub: testUserID,
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
			wantSub: testUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifyRequestTestCase(t, auth, tt)
		})
	}
}

func verifyRequestTestCase(t *testing.T, auth *Auth, tt struct {
	name      string
	header    string
	wantSub   string
	wantError error
}) {
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	if tt.header != "" {
		req.Header.Set("Authorization", tt.header)
	}

	user, err := auth.VerifyRequest(req)
	
	if tt.wantError != nil {
		if !errors.Is(err, tt.wantError) {
			t.Fatalf(verifyRequestMsg, err)
		}
		if user != nil {
			t.Fatalf("VerifyRequest() user = %#v, want nil", user)
		}
		return
	}

	if err != nil {
		t.Fatalf(verifyRequestMsg, err)
	}
	if user == nil {
		t.Fatal("VerifyRequest() user = nil, want non-nil")
	}
	if user.Subject != tt.wantSub {
		t.Fatalf("VerifyRequest() subject = %q, want %q", user.Subject, tt.wantSub)
	}
}

func TestRequireAuth(t *testing.T) {
	auth := newTestAuth(t)
	validToken := createValidToken(t, auth)

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
			wantBody:   testUserID,
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
			requireAuthTestCase(t, auth, tt)
		})
	}
}

func requireAuthTestCase(t *testing.T, auth *Auth, tt struct {
	name       string
	header     string
	wantStatus int
	wantBody   string
	wantCalled bool
}) {
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

	assertRequireAuthResponse(t, rr, called, tt)
}

func assertRequireAuthResponse(t *testing.T, rr *httptest.ResponseRecorder, called bool, tt struct {
	name       string
	header     string
	wantStatus int
	wantBody   string
	wantCalled bool
}) {
	if rr.Code != tt.wantStatus {
		t.Fatalf("RequireAuth() status = %d, want %d", rr.Code, tt.wantStatus)
	}
	if strings.TrimSpace(rr.Body.String()) != strings.TrimSpace(tt.wantBody) {
		t.Fatalf("RequireAuth() body = %q, want %q", rr.Body.String(), tt.wantBody)
	}
	if called != tt.wantCalled {
		t.Fatalf("RequireAuth() called next = %v, want %v", called, tt.wantCalled)
	}
}
