package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	bettergoth "github.com/Protofarm/better-goth"
)

// handleClientCreate creates a new OAuth client for the authenticated user via the OAuth server API.
func handleClientCreate(store *bettergoth.TokenStore, oauthIssuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, ok := accessTokenFromContext(w, r, store)
		if !ok {
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/dashboard?flash=bad_request", http.StatusFound)
			return
		}

		payload := map[string]interface{}{
			"redirect_uris": splitCSV(r.FormValue("redirect_uris")),
			"scopes":        splitCSV(r.FormValue("scopes")),
		}
		if pk := strings.TrimSpace(r.FormValue("public_key_endpoint")); pk != "" {
			payload["public_key_endpoint"] = pk
		}

		status, err := callOAuthClientAPI(http.MethodPost, oauthIssuer, accessToken, payload)
		if err != nil || status != http.StatusCreated {
			http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=create_failed_%d", status), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard?flash=client_created", http.StatusFound)
	})
}

// handleClientRegenerate regenerates the secret for the user's existing OAuth client.
func handleClientRegenerate(store *bettergoth.TokenStore, oauthIssuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, ok := accessTokenFromContext(w, r, store)
		if !ok {
			return
		}

		payload := map[string]interface{}{"regenerate_secret": true}
		status, err := callOAuthClientAPI(http.MethodPatch, oauthIssuer, accessToken, payload)
		if err != nil || status != http.StatusOK {
			http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=regenerate_failed_%d", status), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard?flash=secret_regenerated", http.StatusFound)
	})
}

// handleClientUpdate updates the public key endpoint for the user's OAuth client.
func handleClientUpdate(store *bettergoth.TokenStore, oauthIssuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, ok := accessTokenFromContext(w, r, store)
		if !ok {
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/dashboard?flash=bad_request", http.StatusFound)
			return
		}

		payload := map[string]interface{}{
			"public_key_endpoint": strings.TrimSpace(r.FormValue("public_key_endpoint")),
		}

		status, err := callOAuthClientAPI(http.MethodPatch, oauthIssuer, accessToken, payload)
		if err != nil || status != http.StatusOK {
			http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=update_failed_%d", status), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard?flash=client_updated", http.StatusFound)
	})
}

// handleClientDelete removes the user's OAuth client.
func handleClientDelete(store *bettergoth.TokenStore, oauthIssuer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, ok := accessTokenFromContext(w, r, store)
		if !ok {
			return
		}

		status, err := callOAuthClientAPI(http.MethodDelete, oauthIssuer, accessToken, nil)
		if err != nil || status != http.StatusNoContent {
			http.Redirect(w, r, fmt.Sprintf("/dashboard?flash=delete_failed_%d", status), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard?flash=client_deleted", http.StatusFound)
	})
}

// accessTokenFromContext resolves the authenticated user's OAuth access token from the store.
func accessTokenFromContext(w http.ResponseWriter, r *http.Request, store *bettergoth.TokenStore) (string, bool) {
	user, ok := bettergoth.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return "", false
	}
	rec, found := store.Get(user.Subject)
	if !found || rec.AccessToken == "" {
		http.Redirect(w, r, "/dashboard?flash=no_access_token", http.StatusFound)
		return "", false
	}
	return rec.AccessToken, true
}

// callOAuthClientAPI makes a JSON request to the OAuth server's /oauth/client endpoint.
func callOAuthClientAPI(method, oauthIssuer, accessToken string, payload map[string]interface{}) (int, error) {
	issuer := strings.TrimRight(oauthIssuer, "/")
	target := issuer + "/oauth/client"

	var reqBody *bytes.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return 0, err
		}
		reqBody = bytes.NewReader(data)
	} else {
		reqBody = bytes.NewReader([]byte("{}"))
	}

	req, err := http.NewRequest(method, target, reqBody)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
