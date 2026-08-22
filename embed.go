package bettergoth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Protofarm/better-goth/internal/database"
	oauthserver "github.com/Protofarm/better-goth/internal/oauth-server"
	"github.com/Protofarm/better-goth/internal/oauth-server/handlers"
	"github.com/Protofarm/better-goth/internal/oauth-server/models"
	"github.com/Protofarm/better-goth/internal/oauth-server/smtp"
	"github.com/Protofarm/better-goth/internal/oauth-server/store"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrPasswordTooShort   = store.ErrPasswordTooShort
	ErrUserExists         = store.ErrUserExists
	ErrUsernameExists     = store.ErrUsernameExists
	ErrInvalidCredentials = store.ErrInvalidCredentials
	ErrUserNotFound       = store.ErrUserNotFound
	ErrInvalidOTP         = store.ErrInvalidOTP
)

const (
	TokenUseAccess   = "access"
	TokenUseDevice   = "device"
	TokenUseRecovery = "recovery"

	AccessTokenTTL   = time.Hour
	DeviceTokenTTL   = 30 * 24 * time.Hour
	RecoveryTokenTTL = 15 * time.Minute
)

// EmbedConfig configures an in-process authorization server (no extra listener).
type EmbedConfig struct {
	StorageType        string
	ConnectionString   string
	IssuerURL          string
	KeyDir             string
	ClientID           string
	ClientSecret       string
	RedirectURIs       []string
	CORSOrigins        []string
	DevMode            bool
	SMTP               SMTPConfig
	AdminToken         string
	PrivateKeyJWTHosts []string
	JWTSecret          []byte
}

// SMTPConfig is the public mailer settings for the embedded server.
type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func (c SMTPConfig) internal() smtp.Config {
	return smtp.Config{
		Host:     c.Host,
		Port:     c.Port,
		Username: c.Username,
		Password: c.Password,
		From:     c.From,
	}
}

// User is the public user record returned by the embedded API.
type User struct {
	ID             string
	Email          string
	Name           string
	EmailConfirmed bool
}

// TokenPair is the mobile-session shape issued by the authorization server.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	TokenUse     string
	User         User
}

// NewEmbedded builds store, keys, and an OAuth HTTP handler without ListenAndServe.
func NewEmbedded(cfg EmbedConfig) (*Runtime, error) {
	storageType := strings.TrimSpace(cfg.StorageType)
	if storageType == "" {
		storageType = "memory"
	}
	issuer := strings.TrimSpace(cfg.IssuerURL)
	if issuer == "" {
		issuer = "http://localhost:8080"
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		clientID = "my-client"
	}

	db, err := database.InitDB(storageType, cfg.ConnectionString)
	if err != nil {
		return nil, err
	}

	handler, oauthStore, km, err := oauthserver.CreateOAuthRuntime(db, oauthserver.ServerConfig{
		IssuerURL:          issuer,
		KeyDir:             cfg.KeyDir,
		ClientID:           clientID,
		ClientSecret:       cfg.ClientSecret,
		RedirectURIs:       cfg.RedirectURIs,
		DevMode:            cfg.DevMode,
		SMTPConfig:         cfg.SMTP.internal(),
		CORSOrigins:        cfg.CORSOrigins,
		AdminToken:         cfg.AdminToken,
		PrivateKeyJWTHosts: cfg.PrivateKeyJWTHosts,
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	rt := &Runtime{
		OAuthIssuer:   issuer,
		OAuthClientID: clientID,
		Store:         NewTokenStore(),
		oauthHandler:  handler,
		oauthStore:    oauthStore,
		keyManager:    km,
		db:            db,
		mailer:        smtp.NewMailer(cfg.SMTP.internal()),
	}

	if len(cfg.JWTSecret) > 0 {
		auth, err := NewAuth(cfg.JWTSecret, db)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
		auth.SetDevMode(cfg.DevMode)
		rt.Auth = auth
	}

	return rt, nil
}

// Handler returns the OAuth/OIDC HTTP handler to mount on the process mux.
func (r *Runtime) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return r.oauthHandler
}

// Close releases the embedded database.
func (r *Runtime) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

func (r *Runtime) requireAS() error {
	if r == nil || r.oauthStore == nil || r.keyManager == nil {
		return errors.New("embedded authorization server is not initialized; use NewEmbedded")
	}
	return nil
}

func publicUser(u *models.User) User {
	if u == nil {
		return User{}
	}
	return User{ID: u.ID, Email: u.Email, Name: u.Name, EmailConfirmed: u.EmailConfirmed}
}

func tokenPair(tok *models.Token, user User) *TokenPair {
	use := tok.TokenUse
	if use == "" {
		use = TokenUseAccess
	}
	return &TokenPair{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    tok.ExpiresIn,
		TokenUse:     use,
		User:         user,
	}
}

func (r *Runtime) CreateUser(email, password string) (*User, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, errors.New("email is required")
	}
	u := &models.User{
		Email:        email,
		Name:         email,
		PasswordHash: password,
	}
	if err := r.oauthStore.CreateUser(u); err != nil {
		return nil, err
	}
	out := publicUser(u)
	return &out, nil
}

func (r *Runtime) Authenticate(email, password string) (*User, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	u, err := r.oauthStore.GetUserByCredentials(email, password)
	if err != nil {
		return nil, err
	}
	out := publicUser(u)
	return &out, nil
}

func (r *Runtime) UserByID(id string) (*User, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	u, err := r.oauthStore.GetUserByID(id)
	if err != nil {
		return nil, err
	}
	out := publicUser(u)
	return &out, nil
}

func (r *Runtime) IssueTokens(userID string) (*TokenPair, error) {
	return r.issue(userID, TokenUseAccess, AccessTokenTTL, true)
}

func (r *Runtime) IssueDeviceToken(userID string) (*TokenPair, error) {
	return r.issue(userID, TokenUseDevice, DeviceTokenTTL, false)
}

func (r *Runtime) IssueRecoveryToken(userID string) (*TokenPair, error) {
	return r.issue(userID, TokenUseRecovery, RecoveryTokenTTL, false)
}

func (r *Runtime) issue(userID, tokenUse string, ttl time.Duration, withRefresh bool) (*TokenPair, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	user, err := r.oauthStore.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	tok, err := handlers.IssueUserTokens(r.oauthStore, r.keyManager, r.OAuthIssuer, userID, r.OAuthClientID, "openid profile email", tokenUse, ttl, withRefresh)
	if err != nil {
		return nil, err
	}
	return tokenPair(tok, publicUser(user)), nil
}

func (r *Runtime) Refresh(refreshToken string) (*TokenPair, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	old, err := r.oauthStore.GetByRefreshToken(strings.TrimSpace(refreshToken))
	if err != nil {
		return nil, err
	}
	if time.Now().After(old.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	if old.TokenUse == TokenUseDevice || old.TokenUse == TokenUseRecovery {
		return nil, ErrInvalidToken
	}
	r.oauthStore.RevokePair(old.AccessToken, old.RefreshToken)
	return r.issue(old.UserID, TokenUseAccess, AccessTokenTTL, true)
}

func (r *Runtime) Revoke(accessOrRefresh string) error {
	if err := r.requireAS(); err != nil {
		return err
	}
	r.oauthStore.Revoke(strings.TrimSpace(accessOrRefresh))
	return nil
}

func (r *Runtime) UpdatePassword(userID, password string) error {
	if err := r.requireAS(); err != nil {
		return err
	}
	return r.oauthStore.UpdatePassword(userID, password)
}

func (r *Runtime) DeleteUser(userID string) error {
	if err := r.requireAS(); err != nil {
		return err
	}
	return r.oauthStore.DeleteUser(userID)
}

func (r *Runtime) CreatePasswordResetCode(email string) (string, error) {
	if err := r.requireAS(); err != nil {
		return "", err
	}
	return r.oauthStore.CreatePasswordReset(strings.ToLower(strings.TrimSpace(email)))
}

func (r *Runtime) RequestPasswordReset(email string) error {
	if err := r.requireAS(); err != nil {
		return err
	}
	email = strings.ToLower(strings.TrimSpace(email))
	code, err := r.oauthStore.CreatePasswordReset(email)
	if err != nil {
		return err
	}
	if _, err := r.oauthStore.GetUserByEmail(email); err != nil {
		return nil
	}
	if r.mailer != nil && r.mailer.Enabled() {
		_ = r.mailer.SendPasswordResetEmail(email, code)
	}
	return nil
}

func (r *Runtime) ConsumePasswordReset(email, code string) (*User, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	u, err := r.oauthStore.ConsumePasswordReset(email, code)
	if err != nil {
		return nil, err
	}
	out := publicUser(u)
	return &out, nil
}

func (r *Runtime) VerifyAccessToken(raw string) (*VerifiedUser, error) {
	if err := r.requireAS(); err != nil {
		return nil, err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidToken
	}
	stored, err := r.oauthStore.GetByAccessToken(raw)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	parsed, err := r.keyManager.ParseJWT(raw)
	if err != nil || parsed == nil || !parsed.Valid {
		return nil, ErrInvalidToken
	}
	mapClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	sub, _ := mapClaims["sub"].(string)
	if sub == "" {
		sub = stored.UserID
	}
	tokenUse, _ := mapClaims["token_use"].(string)
	if tokenUse == "" {
		tokenUse = stored.TokenUse
	}
	scope, _ := mapClaims["scope"].(string)
	if scope == "" {
		scope = stored.Scope
	}
	var email string
	if u, err := r.oauthStore.GetUserByID(sub); err == nil {
		email = u.Email
	}
	reg := jwt.RegisteredClaims{Subject: sub}
	if exp, err := mapClaims.GetExpirationTime(); err == nil && exp != nil {
		reg.ExpiresAt = exp
	}
	return &VerifiedUser{
		Subject:  sub,
		Claims:   reg,
		Token:    raw,
		TokenUse: tokenUse,
		Email:    email,
		Scope:    scope,
	}, nil
}

func (r *Runtime) VerifyRequestAccess(req *http.Request) (*VerifiedUser, error) {
	authHeader := strings.TrimSpace(req.Header.Get("Authorization"))
	if authHeader == "" {
		return nil, ErrMissingAuthHeader
	}
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, ErrInvalidAuthHeader
	}
	return r.VerifyAccessToken(parts[1])
}
