package store

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/google/uuid"
)

type Store struct {
	mu      sync.RWMutex
	users   map[string]*models.User
	byName  map[string]*models.User
	byEmail map[string]*models.User
	clients map[string]*models.Client
	codes   map[string]*models.AuthCode
	tokens  map[string]*models.Token
	refresh map[string]*models.Token
}

type Config struct {
	DefaultClientID     string
	DefaultClientSecret string
	DefaultRedirectURIs []string
}

func NewStore(cfg Config) *Store {
	s := &Store{
		users:   make(map[string]*models.User),
		byName:  make(map[string]*models.User),
		byEmail: make(map[string]*models.User),
		clients: make(map[string]*models.Client),
		codes:   make(map[string]*models.AuthCode),
		tokens:  make(map[string]*models.Token),
		refresh: make(map[string]*models.Token),
	}
	s.seed(cfg)
	return s
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

	avatar, _ := models.ParseURL("https://avatars.githubusercontent.com/u/1?v=4")
	//example user - in production, store hashed passwords and use a proper user management system
	u := &models.User{
		ID:        "user-001",
		Username:  "john",
		Password:  "secret", // hash with bcrypt in production
		Email:     "john@example.com",
		Name:      "John Doe",
		AvatarURL: avatar,
	}
	s.users[u.ID] = u
	s.byName[u.Username] = u
	s.byEmail[u.Email] = u

	s.clients[clientID] = &models.Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIs,
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func (s *Store) GetUserByCredentials(ctx context.Context, username, password string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[username]
	if !ok || u.Password != password {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (s *Store) GetClient(ctx context.Context, id string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, errors.New("client not found")
	}
	return c, nil
}

func (s *Store) SaveCode(ctx context.Context, c *models.AuthCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[c.Code] = c
}

func (s *Store) PopCode(ctx context.Context, code string) (*models.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	if !ok {
		return nil, errors.New("code not found")
	}
	delete(s.codes, code) // single-use
	return c, nil
}

func (s *Store) SaveToken(ctx context.Context, t *models.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[t.AccessToken] = t
	if t.RefreshToken != "" {
		s.refresh[t.RefreshToken] = t
	}
}

func (s *Store) GetByAccessToken(ctx context.Context, token string) (*models.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[token]
	if !ok {
		return nil, errors.New("access token not found")
	}
	return t, nil
}

func (s *Store) GetByRefreshToken(ctx context.Context, token string) (*models.Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.refresh[token]
	if !ok {
		return nil, errors.New("refresh token not found")
	}
	return t, nil
}

func (s *Store) RevokeAccessToken(ctx context.Context, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[token]; ok {
		delete(s.refresh, t.RefreshToken)
	}
	delete(s.tokens, token)
}

func (s *Store) CreateUser(ctx context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	user.ID = uuid.New().String()

	if s.byName[user.Username] != nil {
		return errors.New("username already exists")
	}

	if s.byEmail[user.Email] != nil {
		return errors.New("email already registered")
	}

	s.users[user.ID] = user
	s.byName[user.Username] = user
	s.byEmail[user.Email] = user

	if s.users[user.ID] != nil {
		return nil
	}

	return errors.New("unable to create user")
}

func (s *Store) RevokeRefreshToken(ctx context.Context, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refresh, token)
}
