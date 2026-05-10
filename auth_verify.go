package bettergoth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrMissingAuthHeader is returned when the Authorization header is missing.
	ErrMissingAuthHeader = errors.New("missing authorization header")
	// ErrInvalidAuthHeader is returned when the Authorization header is malformed.
	ErrInvalidAuthHeader = errors.New("invalid authorization header")
	// ErrInvalidToken is returned when the JWT token is invalid.
	ErrInvalidToken = errors.New("invalid token")
)

// VerifiedUser represents a user whose token has been verified.
type VerifiedUser struct {
	Subject string
	Claims  jwt.RegisteredClaims
	Token   string
}

type verifiedUserContextKey struct{}

// VerifyToken parses and validates a JWT token string.
func (a *Auth) VerifyToken(tokenString string) (*VerifiedUser, error) {
	if a == nil || len(a.jwtSecret) == 0 {
		return nil, ErrMissingJWTSecret
	}

	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return nil, fmt.Errorf("%w: token is empty", ErrInvalidToken)
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("%w: unexpected signing method", ErrInvalidToken)
		}

		return a.jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if token == nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	if strings.TrimSpace(claims.Subject) == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrInvalidToken)
	}

	return &VerifiedUser{
		Subject: claims.Subject,
		Claims:  *claims,
		Token:   tokenString,
	}, nil
}

// VerifyRequest extracts and verifies the Bearer token from the request's Authorization header.
func (a *Auth) VerifyRequest(r *http.Request) (*VerifiedUser, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return nil, ErrMissingAuthHeader
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, ErrInvalidAuthHeader
	}

	return a.VerifyToken(parts[1])
}

// RequireAuth is a middleware that enforces authentication by verifying the Bearer token in the request.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := a.VerifyRequest(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), verifiedUserContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserFromContext retrieves the VerifiedUser from the context, if present.
func UserFromContext(ctx context.Context) (*VerifiedUser, bool) {
	user, ok := ctx.Value(verifiedUserContextKey{}).(*VerifiedUser)
	if !ok || user == nil {
		return nil, false
	}

	return user, true
}
