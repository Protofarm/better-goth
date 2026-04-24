package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"strings"
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

			action := strings.TrimSpace(r.FormValue("action"))
			switch action {
			case "signup":
				user, err := s.CreateUser(
					r.FormValue("signup_username"),
					r.FormValue("signup_password"),
					r.FormValue("signup_email"),
					r.FormValue("signup_name"),
				)
				if err != nil {
					renderAuthPage(w, authPageData{
						Title:               "Sign in to continue",
						ErrorMessage:        err.Error(),
						ClientID:            clientID,
						RedirectURI:         redirectURI,
						State:               state,
						Scope:               scope,
						CodeChallenge:       codeChallenge,
						CodeChallengeMethod: codeChallengeMethod,
						SignupUsername:      r.FormValue("signup_username"),
						SignupEmail:         r.FormValue("signup_email"),
						SignupName:          r.FormValue("signup_name"),
					})
					return
				}

				renderAuthPage(w, authPageData{
					Title:               "Sign in to continue",
					SuccessMessage:      "Account created for " + user.Username + ". You can now sign in.",
					ClientID:            clientID,
					RedirectURI:         redirectURI,
					State:               state,
					Scope:               scope,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: codeChallengeMethod,
				})
				return
			default:
				// continue with login flow
			}

			user, err := s.GetUserByCredentials(
				r.FormValue("username"),
				r.FormValue("password"),
			)
			if err != nil {
				renderAuthPage(w, authPageData{
					Title:               "Sign in to continue",
					ErrorMessage:        "Invalid username or password.",
					ClientID:            clientID,
					RedirectURI:         redirectURI,
					State:               state,
					Scope:               scope,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: codeChallengeMethod,
					Username:            r.FormValue("username"),
				})
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

		renderAuthPage(w, authPageData{
			Title:               "Sign in to continue",
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               scope,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		})
	}
}

func SignupHandler(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			renderAuthPage(w, authPageData{
				Title:            "Create account",
				StandaloneSignup: true,
			})
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			user, err := s.CreateUser(
				r.FormValue("signup_username"),
				r.FormValue("signup_password"),
				r.FormValue("signup_email"),
				r.FormValue("signup_name"),
			)
			if err != nil {
				renderAuthPage(w, authPageData{
					Title:            "Create account",
					ErrorMessage:     err.Error(),
					StandaloneSignup: true,
					SignupUsername:   r.FormValue("signup_username"),
					SignupEmail:      r.FormValue("signup_email"),
					SignupName:       r.FormValue("signup_name"),
				})
				return
			}

			renderAuthPage(w, authPageData{
				Title:            "Create account",
				SuccessMessage:   "Account created for " + user.Username + ". Return to the app and login with oauthserver.",
				StandaloneSignup: true,
			})
		default:
			http.Error(w, "method_not_allowed", http.StatusMethodNotAllowed)
		}
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

type authPageData struct {
	Title               string
	ErrorMessage        string
	SuccessMessage      string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Username            string
	SignupUsername      string
	SignupEmail         string
	SignupName          string
	StandaloneSignup    bool
}

const authPageHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Authorize</title>
<style>
	body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
	.card{background:#fff;padding:32px;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);width:860px;max-width:96vw}
	h2{margin:0 0 20px;font-size:20px}
	.msg-error{color:#c0392b;margin:0 0 12px}
	.msg-success{color:#0f7a2a;margin:0 0 12px}
	.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
	.panel{border:1px solid #e5e5e5;border-radius:10px;padding:16px}
	.panel h3{margin:0 0 12px;font-size:17px}
	label{display:block;margin-bottom:6px;font-size:14px;color:#555}
	input[type=text],input[type=password],input[type=email]{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #ddd;border-radius:8px;font-size:14px;margin-bottom:12px}
	button{width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:15px;cursor:pointer}
	button:hover{background:#1d4ed8}
	.link{display:inline-block;margin-top:12px;color:#2563eb;text-decoration:none}
	.link:hover{text-decoration:underline}
	@media (max-width: 760px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="card">
	<h2>{{.Title}}</h2>
	{{if .ErrorMessage}}<p class="msg-error">{{.ErrorMessage}}</p>{{end}}
	{{if .SuccessMessage}}<p class="msg-success">{{.SuccessMessage}}</p>{{end}}

	{{if .StandaloneSignup}}
	<div class="panel">
		<h3>Create Account</h3>
		<form method="POST" action="/signup">
			<label>Username</label>
			<input type="text" name="signup_username" autocomplete="username" value="{{.SignupUsername}}" required>
			<label>Email</label>
			<input type="email" name="signup_email" autocomplete="email" value="{{.SignupEmail}}">
			<label>Display Name</label>
			<input type="text" name="signup_name" autocomplete="name" value="{{.SignupName}}">
			<label>Password</label>
			<input type="password" name="signup_password" autocomplete="new-password" required>
			<button type="submit">Create Account</button>
		</form>
		<p style="margin-top:12px;color:#555">After signup, return to your app and start login with <strong>/login/oauthserver</strong>.</p>
	</div>
	{{else}}
	<div class="grid">
		<div class="panel">
			<h3>Sign In</h3>
			<form method="POST">
				<input type="hidden" name="client_id" value="{{.ClientID}}">
				<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
				<input type="hidden" name="state" value="{{.State}}">
				<input type="hidden" name="scope" value="{{.Scope}}">
				<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
				<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
				<label>Username</label>
				<input type="text" name="username" autocomplete="username" value="{{.Username}}" required>
				<label>Password</label>
				<input type="password" name="password" autocomplete="current-password" required>
				<button type="submit">Authorize</button>
			</form>
		</div>
		<div class="panel">
			<h3>Sign Up</h3>
			<form method="POST">
				<input type="hidden" name="action" value="signup">
				<input type="hidden" name="client_id" value="{{.ClientID}}">
				<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
				<input type="hidden" name="state" value="{{.State}}">
				<input type="hidden" name="scope" value="{{.Scope}}">
				<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
				<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
				<label>Username</label>
				<input type="text" name="signup_username" autocomplete="username" value="{{.SignupUsername}}" required>
				<label>Email</label>
				<input type="email" name="signup_email" autocomplete="email" value="{{.SignupEmail}}">
				<label>Display Name</label>
				<input type="text" name="signup_name" autocomplete="name" value="{{.SignupName}}">
				<label>Password</label>
				<input type="password" name="signup_password" autocomplete="new-password" required>
				<button type="submit">Create Account</button>
			</form>
		</div>
	</div>
	{{end}}
</div>
</body>
</html>`

var authPageTemplate = template.Must(template.New("auth-page").Parse(authPageHTML))

func renderAuthPage(w http.ResponseWriter, data authPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := authPageTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render auth page", http.StatusInternalServerError)
	}
}
