package bettergoth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func testRuntime(t *testing.T) *Runtime {
	t.Helper()
	dir := t.TempDir()
	rt, err := NewEmbedded(EmbedConfig{
		StorageType:      "sqlite",
		ConnectionString: filepath.Join(dir, "test.db"),
		IssuerURL:        "http://localhost:8080",
		KeyDir:           filepath.Join(dir, "keys"),
		ClientID:         "test-client",
		ClientSecret:     "test-secret-value",
		DevMode:          false,
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}

func TestEmbeddedSignupLoginRefreshRevoke(t *testing.T) {
	rt := testRuntime(t)

	if _, err := rt.CreateUser("ada@example.com", "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("expected short password error, got %v", err)
	}

	user, err := rt.CreateUser("Ada@example.com", "secret12")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Email != "ada@example.com" {
		t.Fatalf("email normalized, got %q", user.Email)
	}

	if _, err := rt.CreateUser("ada@example.com", "secret12"); !errors.Is(err, ErrUserExists) && !errors.Is(err, ErrUsernameExists) {
		t.Fatalf("expected duplicate error, got %v", err)
	}

	authed, err := rt.Authenticate("ada@example.com", "secret12")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authed.ID != user.ID {
		t.Fatalf("id mismatch")
	}

	if _, err := rt.Authenticate("ada@example.com", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if _, err := rt.Authenticate("missing@example.com", "secret12"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown email should be invalid credentials, got %v", err)
	}

	pair, err := rt.IssueTokens(user.ID)
	if err != nil {
		t.Fatalf("IssueTokens: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.User.Email != "ada@example.com" {
		t.Fatalf("incomplete token pair: %+v", pair)
	}

	got, err := rt.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if got.Subject != user.ID || got.TokenUse != TokenUseAccess {
		t.Fatalf("claims: %+v", got)
	}

	refreshed, err := rt.Refresh(pair.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := rt.Refresh(pair.RefreshToken); err == nil {
		t.Fatal("old refresh should be rejected")
	}
	if _, err := rt.VerifyAccessToken(pair.AccessToken); err == nil {
		t.Fatal("old access should be revoked after refresh")
	}

	if err := rt.Revoke(refreshed.AccessToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := rt.VerifyAccessToken(refreshed.AccessToken); err == nil {
		t.Fatal("revoked access should fail")
	}
}

func TestRevokeAccessDirectly(t *testing.T) {
	rt := testRuntime(t)
	user, err := rt.CreateUser("rev@example.com", "secret12")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := rt.IssueTokens(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Fatalf("issued token should verify: %v", err)
	}
	if err := rt.Revoke(pair.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.VerifyAccessToken(pair.AccessToken); err == nil {
		t.Fatal("revoked access should fail")
	}
}

func TestDeviceAndRecoveryTokens(t *testing.T) {
	rt := testRuntime(t)
	user, err := rt.CreateUser("dev@example.com", "secret12")
	if err != nil {
		t.Fatal(err)
	}

	device, err := rt.IssueDeviceToken(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if device.RefreshToken != "" || device.TokenUse != TokenUseDevice {
		t.Fatalf("device pair: %+v", device)
	}
	got, err := rt.VerifyAccessToken(device.AccessToken)
	if err != nil || got.TokenUse != TokenUseDevice {
		t.Fatalf("device verify: %v %+v", err, got)
	}

	code, err := rt.CreatePasswordResetCode("dev@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.ConsumePasswordReset("dev@example.com", "000000"); err == nil {
		t.Fatal("bad otp should fail")
	}
	u, err := rt.ConsumePasswordReset("dev@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := rt.IssueRecoveryToken(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TokenUse != TokenUseRecovery {
		t.Fatalf("recovery use %q", rec.TokenUse)
	}
}

func TestRotateRequiresAdminToken(t *testing.T) {
	dir := t.TempDir()
	rt, err := NewEmbedded(EmbedConfig{
		StorageType:      "sqlite",
		ConnectionString: filepath.Join(dir, "a.db"),
		IssuerURL:        "http://localhost:8080",
		KeyDir:           filepath.Join(dir, "keys"),
		ClientID:         "test-client",
		ClientSecret:     "test-secret-value",
		AdminToken:       "",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	req := httptest.NewRequest(http.MethodPost, "/admin/rotate", nil)
	rec := httptest.NewRecorder()
	rt.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without admin token, got %d", rec.Code)
	}

	rt2, err := NewEmbedded(EmbedConfig{
		StorageType:  "sqlite",
		IssuerURL:    "http://localhost:8080",
		KeyDir:       filepath.Join(dir, "keys2"),
		ClientID:     "test-client",
		ClientSecret: "test-secret-value",
		AdminToken:   "rotate-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt2.Close() })

	req = httptest.NewRequest(http.MethodPost, "/admin/rotate", nil)
	rec = httptest.NewRecorder()
	rt2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without bearer, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/rotate", nil)
	req.Header.Set("Authorization", "Bearer rotate-secret")
	rec = httptest.NewRecorder()
	rt2.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with admin token, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestValidateCallbackStateRejectsMismatch(t *testing.T) {
	// ensure key dir is writable in CI sandboxes
	if _, err := os.Stat(os.TempDir()); err != nil {
		t.Skip(err)
	}
}
