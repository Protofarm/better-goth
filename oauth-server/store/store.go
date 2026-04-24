package store

import (
	"errors"
	"sync"

	"github.com/Protofarm/better-goth/oauth-server/models"
)

type Store struct {
	mu      sync.RWMutex
	users   map[string]*models.User
	byName  map[string]*models.User
	clients map[string]*models.Client
	codes   map[string]*models.AuthCode
	tokens  map[string]*models.Token
	refresh map[string]*models.Token
}

func NewStore() *Store {
	s := &Store{
		users:   make(map[string]*models.User),
		byName:  make(map[string]*models.User),
		clients: make(map[string]*models.Client),
		codes:   make(map[string]*models.AuthCode),
		tokens:  make(map[string]*models.Token),
		refresh: make(map[string]*models.Token),
	}
	s.seed()
	return s
}

func (s *Store) seed() {
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

	s.clients["my-client"] = &models.Client{
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func (s *Store) GetUserByCredentials(username, password string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[username]
	if !ok || u.Password != password {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

func (s *Store) GetUserByID(id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
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
