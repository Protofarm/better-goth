package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"strings"
	"sync"

	"github.com/Protofarm/better-goth/database"
	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/providers"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	db *database.Instance

	// in-memory or cached
	codesMu sync.RWMutex
	codes   map[string]*models.AuthCode

	tokensMu sync.RWMutex
	tokens   map[string]*models.Token

	refreshMu sync.RWMutex
	refresh   map[string]*models.Token
}

type Config struct {
	DefaultClientID     string
	DefaultClientSecret string
	DefaultRedirectURIs []string
	DevMode             bool
}

func NewStore(db *database.Instance, cfg Config) *Store {
	s := &Store{
		db:      db,
		codes:   make(map[string]*models.AuthCode),
		tokens:  make(map[string]*models.Token),
		refresh: make(map[string]*models.Token),
	}
	s.seed(cfg)
	return s
}

// hashPassword hashes a password using bcrypt with cost 12
func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashed), err
}

// verifyPassword compares a plaintext password with a bcrypt hash
func verifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (s *Store) seed(cfg Config) {
	clientID := strings.TrimSpace(cfg.DefaultClientID)
	if clientID == "" {
		clientID = "my-client"
	}

	clientSecret := strings.TrimSpace(cfg.DefaultClientSecret)
	if clientSecret == "" {
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
	u := &models.User{
		ID:           "user-001",
		Name:         "john",
		PasswordHash: "secret",
		Email:        "john@example.com",
		GivenName:    "John Doe",
		Picture:      "https://avatars.githubusercontent.com/u/1?v=4",
	}
	if err := s.CreateUser(u); err != nil {
		log.Printf("Unable to create dummy user: %v", err)
	}

	if err := s.db.CreateClient(&models.Client{
		ID:           clientID,
		UserID:       u.ID,
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIs,
		Scopes:       []string{"openid", "profile", "email"},
	}); err != nil {
		log.Printf("Unable to create dummy client: %v", err)
	}
}

func (s *Store) CreateUser(user *models.User) error {
	user.ID = uuid.New().String()
	hash, err := hashPassword(user.PasswordHash)
	if err != nil {
		return err
	}
	user.PasswordHash = hash

	if err := s.db.CreateUser(user); err != nil {
		if strings.Contains(err.Error(), "duplicate key") ||
			strings.Contains(err.Error(), "UNIQUE constraint") {
			if strings.Contains(err.Error(), "name") {
				return errors.New("username already exists")
			}
			if strings.Contains(err.Error(), "email") {
				return errors.New("email already registered")
			}
		}
		return err
	}

	// create oauthuser entry
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
	u, err := s.db.GetUserByName(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("User not found")
		}
		return nil, err
	}

	ok := s.db.CheckUserIdentityExists(u.ID)
	if !ok {
		return nil, errors.New("invalid login method")
	}

	if err := verifyPassword(u.PasswordHash, password); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

func (s *Store) GetUserByID(id string) (*models.User, error) {
	user, err := s.db.GetUserByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("User not found")
		}
	}
	return user, nil
}

func (s *Store) GetClient(id string) (*models.Client, error) {
	client, err := s.db.GetClientByID(id)
	if err == nil {
		return client, nil
	}
	return nil, errors.New("client not found")
}

func (s *Store) GetClientByUserID(userID string) (*models.Client, error) {
	client, err := s.db.GetClientByUserID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("Client not found")
		}
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
		log.Printf("Updated client %s. Regenerated secret: %s", id, secret)
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
	log.Printf("Created client %s for user %s. Generated secret: %s", client.ID, userID, secret)
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
	delete(s.codes, code) // single-use
	return c, nil
}

func (s *Store) SaveToken(t *models.Token) {
	s.tokensMu.Lock()
	s.tokens[t.AccessToken] = t
	s.tokensMu.Unlock()

	if t.RefreshToken != "" {
		s.refreshMu.Lock()
		s.refresh[t.RefreshToken] = t
		s.refreshMu.Unlock()
	}
}

func (s *Store) GetByAccessToken(token string) (*models.Token, error) {
	s.tokensMu.RLock()
	defer s.tokensMu.RUnlock()
	t, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("access token not found")
	}
	return t, nil
}

func (s *Store) GetByRefreshToken(token string) (*models.Token, error) {
	s.refreshMu.RLock()
	defer s.refreshMu.RUnlock()
	t, ok := s.refresh[token]
	if !ok {
		return nil, errors.New("refresh token not found")
	}
	return t, nil
}

func (s *Store) RevokeAccessToken(token string) {
	s.tokensMu.Lock()
	t, ok := s.tokens[token]
	delete(s.tokens, token)
	s.tokensMu.Unlock()

	if ok && t.RefreshToken != "" {
		s.refreshMu.Lock()
		delete(s.refresh, t.RefreshToken)
		s.refreshMu.Unlock()
	}
}

func (s *Store) RevokeRefreshToken(token string) {
	s.refreshMu.Lock()
	t, ok := s.refresh[token]
	delete(s.refresh, token)
	s.refreshMu.Unlock()

	if ok {
		s.tokensMu.Lock()
		delete(s.tokens, t.AccessToken)
		s.tokensMu.Unlock()
	}
}

func generateClientSecret(size int) (string, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
