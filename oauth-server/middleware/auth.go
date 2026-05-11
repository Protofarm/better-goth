package middleware

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
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
				errs.WriteError(w, http.StatusUnauthorized, errs.CodeMissingToken, errs.ResourceErrorMessages[errs.CodeMissingToken])
				return
			}
			raw := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf(errs.MsgUnexpectedSigningMethod, t.Header["alg"])
				}
				return pubKey, nil
			}, jwt.WithValidMethods([]string{"RS256"}))

			if err != nil || !token.Valid {
				errs.WriteError(w, http.StatusUnauthorized, errs.CodeInvalidToken, errs.ResourceErrorMessages[errs.CodeInvalidToken])
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				errs.WriteError(w, http.StatusUnauthorized, errs.CodeInvalidToken, "Could not parse claims")
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
