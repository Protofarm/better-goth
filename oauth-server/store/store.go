package store

import (
	"database/sql"
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
	mu sync.RWMutex
	db *database.Instance

	// in-memory or DB
	clients map[string]*models.Client

	// in-memory or cached
	codes   map[string]*models.AuthCode
	tokens  map[string]*models.Token
	refresh map[string]*models.Token
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
		clients: make(map[string]*models.Client),
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

	hashedPassword, _ := hashPassword("secret")

	//example user - in production, store hashed passwords and use a proper user management system
	u := &models.User{
		ID:           "user-001",
		Name:         "john",
		PasswordHash: hashedPassword,
		Email:        "john@example.com",
		GivenName:    "John Doe",
		Picture:      "https://avatars.githubusercontent.com/u/1?v=4",
	}
	if err := s.CreateUser(u); err != nil {
		log.Printf("Unable to create dummy user: %v", err)
	}

	s.clients[clientID] = &models.Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIs,
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func (s *Store) CreateUser(user *models.User) error {
	user.ID = uuid.New().String()
	hash, err := hashPassword(user.PasswordHash)
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, errors.New("client not found")
	}
	return c, nil
}

func (s *Store) SaveCode(c *models.AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.Code] = c
}

func (s *Store) PopCode(code string) (*models.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, errors.New("code not found")
	}
	delete(s.codes, code) // single-use
	return c, nil
}

func (s *Store) SaveToken(t *models.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.AccessToken] = t
	if t.RefreshToken != "" {
		s.refresh[t.RefreshToken] = t
	}
}

func (s *Store) GetByAccessToken(token string) (*models.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("access token not found")
	}
	return t, nil
}

func (s *Store) GetByRefreshToken(token string) (*models.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.refresh[token]
	if !ok {
		return nil, errors.New("refresh token not found")
	}
	return t, nil
}

func (s *Store) RevokeAccessToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[token]; ok {
		delete(s.refresh, t.RefreshToken)
	}
	delete(s.tokens, token)
}

func (s *Store) RevokeRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.refresh[token]; ok {
		delete(s.tokens, t.AccessToken)
	}
	delete(s.refresh, token)
}
