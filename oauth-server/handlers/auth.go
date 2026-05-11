package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"time"

	errs "github.com/Protofarm/better-goth/oauth-server/errors"
	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/oauth-server/store"
)

func AuthorizeHandler(s *store.Store, devMode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		state := q.Get("state")
		scope := q.Get("scope")
		responseType := q.Get("response_type")
		nonce := q.Get("nonce")
		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")

		// RFC 6749 Section 3.1.1: response_type is required
		if responseType != "code" {
			// Cannot redirect without valid redirect_uri, so return direct error
			errs.HTTPError(w, errs.JSONErrUnsupportedResponseType, http.StatusBadRequest)
			return
		}

		// RFC 6749 Section 3.1.1: client_id is required
		client, err := s.GetClient(clientID)
		if err != nil {
			errs.HTTPError(w, errs.JSONErrInvalidClient, http.StatusBadRequest)
			return
		}

		// RFC 6749 Section 3.1.2.1: redirect_uri must be registered
		if !isValidRedirect(client.RedirectURIs, redirectURI, devMode) {
			errs.HTTPError(w, errs.JSONErrInvalidRedirectURI, http.StatusBadRequest)
			return
		}

		// RFC 6749 Section 3.1.1: state is required (best practice, enforced here)
		if state == "" {
			errs.RedirectError(w, r, redirectURI, errs.CodeInvalidRequest, errs.MsgStateRequired, "")
			return
		}
		if codeChallenge == "" {
			errs.RedirectError(w, r, redirectURI, errs.CodeInvalidRequest,
				errs.MsgCodeChallengeRequired, state)
			return
		}

		if codeChallengeMethod != "S256" {
			errs.RedirectError(w, r, redirectURI, errs.CodeInvalidRequest,
				errs.MsgOnlyS256Allowed, state)
			return
		}

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			var (
				user *models.User
				err  error
				msg  string
			)

			if signupUsername := r.FormValue("signup_username"); signupUsername != "" {
				user = &models.User{Username: signupUsername, Email: r.FormValue("signup_email"), Name: r.FormValue("signup_name"), Password: r.FormValue("signup_password")}
				err = s.CreateUser(user)
				msg = "Username or email already taken."

			} else {
				user, err = s.GetUserByCredentials(
					r.FormValue("username"),
					r.FormValue("password"),
				)
				msg = "Invalid username or password."
			}
			if err != nil {
				renderAuthPage(w, authPageData{
					Title:               "Sign in to continue",
					ErrorMessage:        msg,
					ClientID:            clientID,
					RedirectURI:         redirectURI,
					State:               state,
					Scope:               scope,
					Nonce:               nonce,
					CodeChallenge:       codeChallenge,
					CodeChallengeMethod: codeChallengeMethod,
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
				Nonce:               nonce,
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
			Nonce:               nonce,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
		})
	}
}

func isValidRedirect(allowed []string, uri string, devMode bool) bool {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return false
	}

	hostname := parsedURI.Hostname()
	isLoopback := hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"

	if !devMode && !isLoopback && parsedURI.Scheme != "https" {
		return false
	}

	for _, a := range allowed {
		if a == uri {
			return true
		}
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
	Nonce               string
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
	.consent{margin:0 0 24px;padding:24px 24px 20px;border:1px solid #c7d2fe;border-radius:16px;background:linear-gradient(180deg,#eff6ff 0%,#ffffff 100%);box-shadow:0 10px 24px rgba(37,99,235,.12)}
	.consent-eyebrow{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;margin-bottom:12px}
	.consent h3{margin:0 0 8px;font-size:24px;line-height:1.15;color:#0f172a}
	.consent p{margin:0 0 14px;color:#334155;font-size:15px;line-height:1.5;max-width:56ch}
	.consent ul{list-style:none;margin:0;padding:0;display:grid;gap:10px}
	.consent li{display:flex;align-items:flex-start;gap:10px;padding:12px 14px;border:1px solid #dbe4ff;border-radius:12px;background:#fff;color:#0f172a;font-size:15px;line-height:1.45}
	.consent li::before{content:"";flex:0 0 20px;width:20px;height:20px;margin-top:1px;border-radius:999px;background:#2563eb url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20' fill='none'%3E%3Cpath d='M8.1 13.2 5.2 10.3l-1.2 1.2 4.1 4.1L16 7.7l-1.2-1.2-6.7 6.7z' fill='%23fff'/%3E%3C/svg%3E") center/12px 12px no-repeat;box-shadow:0 4px 10px rgba(37,99,235,.25)}
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

	{{if not .StandaloneSignup}}
	<div class="consent">
		<div class="consent-eyebrow">Review access</div>
		<h3>Authorize "MyApp" to:</h3>
		<ul>
			<li>See your email address</li>
			<li>Access your profile</li>
			<li>Offline access</li>
		</ul>
	</div>
	{{end}}

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
				<input type="hidden" name="nonce" value="{{.Nonce}}">
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
				<input type="hidden" name="nonce" value="{{.Nonce}}">
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
