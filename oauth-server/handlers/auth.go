package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

func AuthorizeHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		scope := q.Get("scope")
		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")

		client, err := s.GetClient(clientID)
		if err != nil {
			http.Error(w, "invalid_client", http.StatusBadRequest)
			return
		}

		if !isValidRedirect(client.RedirectURIs, redirectURI) {
			http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
			return
		}

		if state == "" {
			redirectWithError(w, r, redirectURI, "invalid_request", "state is required", "")
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			user, err := s.GetUserByCredentials(
				r.FormValue("username"),
				r.FormValue("password"),
			)
			if err != nil {
				renderLogin(w, "Invalid username or password.", clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod)
				return
			}

			// Generate single-use auth code
			b := make([]byte, 16)
			rand.Read(b)
			code := hex.EncodeToString(b)

			s.SaveCode(&models.AuthCode{
				Code:                code,
				ClientID:            clientID,
				UserID:              user.ID,
				RedirectURI:         redirectURI,
				Scope:               scope,
				ExpiresAt:           time.Now().Add(5 * time.Minute),
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
			})

			dest, _ := url.Parse(redirectURI)
			params := url.Values{}
			params.Set("code", code)
			params.Set("state", state)
			dest.RawQuery = params.Encode()
			http.Redirect(w, r, dest.String(), http.StatusFound)
			return
		}

		renderLogin(w, "", clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod)
	}
}

func isValidRedirect(allowed []string, uri string) bool {
	for _, a := range allowed {
		if a == uri {
			return true
		}
	}
	return false
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, errCode, desc, state string) {
	dest, _ := url.Parse(redirectURI)
	p := url.Values{}
	p.Set("error", errCode)
	p.Set("error_description", desc)
	if state != "" {
		p.Set("state", state)
	}
	dest.RawQuery = p.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func verifyPKCE(method, challenge, verifier string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain", "":
		return verifier == challenge
	}
	return false
}

func renderLogin(w http.ResponseWriter, errMsg, clientID, redirectURI, state, scope, codeChallenge, codeChallengeMethod string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	errHTML := ""
	if errMsg != "" {
		errHTML = `<p style="color:#c0392b;margin-bottom:12px;">` + errMsg + `</p>`
	}

	w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Authorize</title>
<style>
  body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
  .card{background:#fff;padding:36px;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);width:360px}
  h2{margin:0 0 24px;font-size:20px}
  label{display:block;margin-bottom:6px;font-size:14px;color:#555}
  input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px;margin-bottom:16px}
  button{width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:15px;cursor:pointer}
  button:hover{background:#1d4ed8}
</style></head><body>
<div class="card">
  <h2>Sign in to continue</h2>
  ` + errHTML + `
  <form method="POST">
    <input type="hidden" name="client_id"             value="` + clientID + `">
    <input type="hidden" name="redirect_uri"           value="` + redirectURI + `">
    <input type="hidden" name="state"                  value="` + state + `">
    <input type="hidden" name="scope"                  value="` + scope + `">
    <input type="hidden" name="code_challenge"         value="` + codeChallenge + `">
    <input type="hidden" name="code_challenge_method"  value="` + codeChallengeMethod + `">
    <label>Username</label>
    <input type="text"     name="username" autocomplete="username"      required>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Authorize</button>
  </form>
</div>
</body></html>`))
}
