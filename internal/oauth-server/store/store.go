package store

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Protofarm/better-goth/internal/database"
	"github.com/Protofarm/better-goth/internal/oauth-server/models"
	"github.com/Protofarm/better-goth/internal/providers"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	MinPasswordLength = 8
	bcryptCost        = 12
	otpTTL            = 10 * time.Minute
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordTooShort   = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrUserExists         = errors.New("email already registered")
	ErrUsernameExists     = errors.New("username already exists")
	ErrClientNotFound     = errors.New("client not found")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidOTP         = errors.New("invalid or expired code")
)

type Store struct {
	db *database.Instance

	codesMu sync.RWMutex
	codes   map[string]*models.AuthCode
}

type Config struct {
	DefaultClientID     string
	DefaultClientSecret string
	DefaultRedirectURIs []string
	DevMode             bool
}

func NewStore(db *database.Instance, cfg Config) *Store {
	s := &Store{
		db:    db,
		codes: make(map[string]*models.AuthCode),
	}
	s.seed(cfg)
	return s
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	return string(hashed), err
}

func verifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Store) seed(cfg Config) {
	clientID := strings.TrimSpace(cfg.DefaultClientID)
	if clientID == "" {
		clientID = "my-client"
	}

	clientSecret := strings.TrimSpace(cfg.DefaultClientSecret)
	if clientSecret == "" {
		if !cfg.DevMode {
			log.Printf("oauth client secret is empty; set providers.oauthserver.client_secret")
		}
		clientSecret = "my-secret"
	}

	redirectURIs := make([]string, 0, len(cfg.DefaultRedirectURIs))
	for _, uri := range cfg.DefaultRedirectURIs {
		trimmed := strings.TrimSpace(uri)
		if trimmed != "" {
			redirectURIs = append(redirectURIs, trimmed)
		}
	}
	if len(redirectURIs) == 0 {
		redirectURIs = []string{"http://localhost:3000/callback/oauthserver"}
	}

	owner, err := s.db.GetUserByEmail("oauth-client@localhost")
	if err != nil {
		owner = &models.User{
			Name:         "oauth-client",
			PasswordHash: randomPassword(),
			Email:        "oauth-client@localhost",
			GivenName:    "OAuth Client",
		}
		if err := s.CreateUser(owner); err != nil {
			if existing, getErr := s.db.GetUserByEmail(owner.Email); getErr == nil {
				owner = existing
			} else {
				log.Printf("Unable to create oauth client owner: %v", err)
				return
			}
		}
	}

	if _, err := s.db.GetClientByID(clientID); err != nil {
		if err := s.db.CreateClient(&models.Client{
			ID:           clientID,
			UserID:       owner.ID,
			ClientSecret: clientSecret,
			RedirectURIs: redirectURIs,
			Scopes:       []string{"openid", "profile", "email"},
		}); err != nil {
			log.Printf("Unable to create oauth client: %v", err)
		}
	}

	if !cfg.DevMode {
		return
	}

	u := &models.User{
		Name:         "john",
		PasswordHash: "password1",
		Email:        "john@example.com",
		GivenName:    "John Doe",
		Picture:      "https://avatars.githubusercontent.com/u/1?v=4",
	}
	if err := s.CreateUser(u); err != nil {
		log.Printf("Unable to create dummy user: %v", err)
	}
}

func randomPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "dev-only-change-me-please"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Store) CreateUser(user *models.User) error {
	if len(user.PasswordHash) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.Email = strings.ToLower(strings.TrimSpace(user.Email))
	user.Name = strings.TrimSpace(user.Name)
	if user.Name == "" {
		user.Name = user.Email
	}

	hash, err := hashPassword(user.PasswordHash)
	if err != nil {
		return err
	}
	user.PasswordHash = hash

	if err := s.db.CreateUser(user); err != nil {
		if strings.Contains(err.Error(), "duplicate key") ||
			strings.Contains(err.Error(), "UNIQUE constraint") {
			if strings.Contains(err.Error(), "name") {
				return ErrUsernameExists
			}
			if strings.Contains(err.Error(), "email") {
				return ErrUserExists
			}
		}
		return err
	}

	ui := &models.UserIdentity{
		ID:       uuid.New().String(),
		UserID:   user.ID,
		Sub:      user.ID,
		Provider: providers.OAuthServerProviderName,
	}
	if err = s.db.CreateUserIdentity(ui); err != nil {
		if strings.Contains(err.Error(), "duplicate key") ||
			strings.Contains(err.Error(), "UNIQUE constraint") {
			return errors.New("user identity already exists")
		}
		return err
	}

	return nil
}

func (s *Store) ConfirmUserEmail(userID string) error {
	return s.db.ConfirmEmailByUserID(userID)
}

func (s *Store) GetUserByCredentials(username, password string) (*models.User, error) {
	username = strings.TrimSpace(username)
	lookup := strings.ToLower(username)

	var (
		u   *models.User
		err error
	)
	if strings.Contains(lookup, "@") {
		u, err = s.db.GetUserByEmail(lookup)
	} else {
		u, err = s.db.GetUserByName(username)
		if err != nil && errors.Is(err, sql.ErrNoRows) {
			u, err = s.db.GetUserByEmail(lookup)
		}
	}
	if err != nil {
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$0123456789abcdef012345u0h6s9t1u2v3w4x5y6z7a8b9c0d1e2"), []byte(password))
		return nil, ErrInvalidCredentials
	}

	if !s.db.CheckUserIdentityExists(u.ID) {
		return nil, ErrInvalidCredentials
	}

	if err := verifyPassword(u.PasswordHash, password); err != nil {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

func (s *Store) GetUserByID(id string) (*models.User, error) {
	user, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	user, err := s.db.GetUserByEmail(strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *Store) UpdatePassword(userID, plaintext string) error {
	if len(plaintext) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	hash, err := hashPassword(plaintext)
	if err != nil {
		return err
	}
	if err := s.db.UpdateUserPassword(userID, hash); err != nil {
		return err
	}
	return s.RevokeAllForUser(userID)
}

func (s *Store) DeleteUser(userID string) error {
	return s.db.DeleteUser(userID)
}

func (s *Store) GetClient(id string) (*models.Client, error) {
	client, err := s.db.GetClientByID(id)
	if err == nil {
		return client, nil
	}
	return nil, ErrClientNotFound
}

func (s *Store) AuthenticateClient(id, secret string) (*models.Client, error) {
	client, err := s.GetClient(id)
	if err != nil {
		return nil, err
	}
	if !secureCompare(client.ClientSecret, secret) {
		return nil, errors.New("client authentication failed")
	}
	return client, nil
}

func (s *Store) GetClientByUserID(userID string) (*models.Client, error) {
	client, err := s.db.GetClientByUserID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("Client not found")
		}
		return nil, err
	}
	return client, nil
}

func (s *Store) UpdateClient(id, publicKeyEndpoint string, scope, redirectURIs []string, regenerateSecret bool) (*models.Client, error) {
	existingClient, err := s.db.GetClientByID(id)
	if err != nil {
		return nil, errors.New("client not found")
	}

	if publicKeyEndpoint != "" {
		existingClient.PublicKeyEndpoint = publicKeyEndpoint
	}
	if scope != nil {
		existingClient.Scopes = models.StringList(scope)
	}
	if redirectURIs != nil {
		existingClient.RedirectURIs = models.StringList(redirectURIs)
	}
	if regenerateSecret {
		secret, err := generateClientSecret(16)
		if err != nil {
			return nil, err
		}
		existingClient.ClientSecret = secret
	}

	err = s.db.UpdateClient(existingClient)
	if err != nil {
		return nil, err
	}
	return existingClient, nil
}

func (s *Store) DeleteClient(id string) error {
	return s.db.DeleteClient(id)
}

func (s *Store) CreateClient(userID, publicKeyEndpoint string, scopes, redirectURIs []string) (*models.Client, error) {
	secret, err := generateClientSecret(16)
	if err != nil {
		return nil, err
	}
	client := &models.Client{
		ID:                uuid.New().String(),
		UserID:            userID,
		ClientSecret:      secret,
		PublicKeyEndpoint: publicKeyEndpoint,
		RedirectURIs:      models.StringList(redirectURIs),
		Scopes:            models.StringList(scopes),
	}
	err = s.db.CreateClient(client)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (s *Store) SaveCode(c *models.AuthCode) {
	s.codesMu.Lock()
	defer s.codesMu.Unlock()
	s.codes[c.Code] = c
}

func (s *Store) PopCode(code string) (*models.AuthCode, error) {
	s.codesMu.Lock()
	defer s.codesMu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, errors.New("code not found")
	}
	delete(s.codes, code)
	return c, nil
}

func (s *Store) identityIDForUser(userID string) (string, error) {
	identity, err := s.db.GetIdentityByUserID(userID)
	if err == nil {
		return identity.ID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	ui := &models.UserIdentity{
		ID:       uuid.New().String(),
		UserID:   userID,
		Sub:      userID,
		Provider: providers.OAuthServerProviderName,
	}
	if err := s.db.CreateUserIdentity(ui); err != nil {
		return "", err
	}
	return ui.ID, nil
}

func (s *Store) SaveToken(t *models.Token) {
	if t == nil {
		return
	}
	identityID, err := s.identityIDForUser(t.UserID)
	if err != nil {
		log.Printf("failed to resolve identity for token persist: %v", err)
		identityID = t.UserID
	}
	use := t.TokenUse
	if use == "" {
		use = "access"
	}
	row := &models.DBToken{
		ID:           uuid.New().String(),
		IdentityID:   identityID,
		UserID:       t.UserID,
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		TokenUse:     use,
		ExpiresIn:    t.ExpiresIn,
		Scope:        t.Scope,
		Nonce:        t.Nonce,
		ClientID:     t.ClientID,
		ExpiresAt:    t.ExpiresAt,
	}
	if err := s.db.SaveToken(row); err != nil {
		log.Printf("failed to persist token: %v", err)
	}
}

func (s *Store) GetByAccessToken(token string) (*models.Token, error) {
	row, err := s.db.GetTokenByAccess(token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("access token not found")
		}
		return nil, err
	}
	return row.ToToken(), nil
}

func (s *Store) GetByRefreshToken(token string) (*models.Token, error) {
	row, err := s.db.GetTokenByRefresh(token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}
	return row.ToToken(), nil
}

func (s *Store) RevokeAccessToken(token string) {
	if err := s.db.DeleteTokenByAccessOrRefresh(token, ""); err != nil {
		log.Printf("failed to revoke access token: %v", err)
	}
}

func (s *Store) RevokeRefreshToken(token string) {
	if err := s.db.DeleteTokenByAccessOrRefresh("", token); err != nil {
		log.Printf("failed to revoke refresh token: %v", err)
	}
}

func (s *Store) Revoke(token string) {
	if token == "" {
		return
	}
	if err := s.db.DeleteTokenByAccessOrRefresh(token, token); err != nil {
		log.Printf("failed to revoke token: %v", err)
	}
}

func (s *Store) RevokePair(access, refresh string) {
	if err := s.db.DeleteTokenByAccessOrRefresh(access, refresh); err != nil {
		log.Printf("failed to revoke token pair: %v", err)
	}
}

func (s *Store) RevokeAllForUser(userID string) error {
	return s.db.DeleteTokensByUserID(userID)
}

func (s *Store) CreatePasswordReset(email string) (string, error) {
	n := make([]byte, 4)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	codeNum := int(n[0])<<16 | int(n[1])<<8 | int(n[2])
	code := fmt.Sprintf("%06d", codeNum%1000000)

	user, err := s.GetUserByEmail(email)
	if err != nil {
		_, _ = hashPassword(code)
		return code, nil
	}

	hash, err := hashPassword(code)
	if err != nil {
		return "", err
	}
	pr := &models.PasswordReset{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     user.Email,
		CodeHash:  hash,
		ExpiresAt: time.Now().Add(otpTTL),
	}
	if err := s.db.SavePasswordReset(pr); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Store) ConsumePasswordReset(email, code string) (*models.User, error) {
	pr, err := s.db.LatestPasswordReset(strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return nil, ErrInvalidOTP
	}
	if pr.Used || time.Now().After(pr.ExpiresAt) {
		return nil, ErrInvalidOTP
	}
	if err := verifyPassword(pr.CodeHash, strings.TrimSpace(code)); err != nil {
		return nil, ErrInvalidOTP
	}
	if err := s.db.MarkPasswordResetUsed(pr.ID); err != nil {
		return nil, err
	}
	return s.GetUserByID(pr.UserID)
}

func generateClientSecret(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
