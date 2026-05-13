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

func AuthorizeHandler(s *store.Store, devMode bool, templatePath string) http.HandlerFunc {
	if authPageTemplate == nil {
		if err := InitAuthTemplate(templatePath); err != nil {
			panic("failed to load auth template: " + err.Error())
		}
	}
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

var authPageTemplate *template.Template

func InitAuthTemplate(templatePath string) error {
	var err error
	authPageTemplate, err = template.ParseFiles(templatePath)
	return err
}

func renderAuthPage(w http.ResponseWriter, data authPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := authPageTemplate.Execute(w, data); err != nil {
		http.Error(w, "failed to render auth page", http.StatusInternalServerError)
	}
}
