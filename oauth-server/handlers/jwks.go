package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
)

// JWKSHandler serves GET /.well-known/jwks.json so any client can fetch
// the public key and verify JWTs locally without calling /userinfo.
func JWKSHandler(pub *rsa.PublicKey) http.HandlerFunc {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(
		big.NewInt(int64(pub.E)).Bytes(),
	)

	jwks, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": "default",
				"n":   n,
				"e":   e,
			},
		},
	})

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(jwks)
	}
}
