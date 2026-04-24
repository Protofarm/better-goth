package middleware

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const ClaimsKey contextKey = "jwt_claims"

// RequireAuth returns an http.Handler middleware that validates a Bearer JWT
// signed with the provided RSA public key. Claims are stored in the request
// context under ClaimsKey and can be retrieved with ClaimsFromContext.
func RequireAuth(pubKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				writeErr(w, http.StatusUnauthorized, "missing_token", "Authorization header must be Bearer <token>")
				return
			}
			raw := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("unexpected signing method: %s", t.Header["alg"])
				}
				return pubKey, nil
			}, jwt.WithValidMethods([]string{"RS256"}))

			if err != nil || !token.Valid {
				writeErr(w, http.StatusUnauthorized, "invalid_token", "Token validation failed")
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				writeErr(w, http.StatusUnauthorized, "invalid_token", "Could not parse claims")
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves the JWT MapClaims stored by RequireAuth.
func ClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	c, ok := ctx.Value(ClaimsKey).(jwt.MapClaims)
	return c, ok
}

func writeErr(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s"`, errCode))
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, errCode, description)
}
