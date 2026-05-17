package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"

	"github.com/Protofarm/better-goth/oauth-server/keys"
)

// JWKSHandler serves GET /.well-known/jwks.json so any client can fetch
// the public key and verify JWTs locally without calling /userinfo.
func JWKSHandler(km *keys.KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		infos := km.GetKeyInfos()

		var jwks []map[string]string
		for _, key := range infos {
			pub := key.PubKey
			n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(
				big.NewInt(int64(pub.E)).Bytes(),
			)

			jwks = append(jwks, map[string]string{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": key.Kid,
				"n":   n,
				"e":   e,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": jwks,
		}); err != nil {
			log.Printf("failed to write JWKS response: %v", err)
		}
	}
}
