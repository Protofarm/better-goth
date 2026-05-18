package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"net/url"
	"strings"
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
		req := readAuthorizeRequest(r)
		if !validateAuthorizeRequest(w, r, s, req, devMode) {
			return
		}

		if r.Method != http.MethodPost {
			renderAuthorizePage(w, req, authFormState{})
			return
		}

		handleAuthorizeSubmission(w, r, s, req)
	}
}

type authorizeRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	ResponseType        string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type authFormState struct {
	ErrorMessage   string
	Username       string
	SignupUsername string
	SignupEmail    string
	SignupName     string
}

func readAuthorizeRequest(r *http.Request) authorizeRequest {
	q := r.URL.Query()
	return authorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		Scope:               normalizeScope(q.Get("scope")),
		ResponseType:        q.Get("response_type"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
}

func validateAuthorizeRequest(w http.ResponseWriter, r *http.Request, s *store.Store, req authorizeRequest, devMode bool) bool {
	if req.ResponseType != "code" {
		errs.HTTPError(w, errs.JSONErrUnsupportedResponseType, http.StatusBadRequest)
		return false
	}

	client, err := s.GetClient(req.ClientID)
	if err != nil {
		errs.HTTPError(w, errs.JSONErrInvalidClient, http.StatusBadRequest)
		return false
	}

	if !isValidRedirect(client.RedirectURIs, req.RedirectURI, devMode) {
		errs.HTTPError(w, errs.JSONErrInvalidRedirectURI, http.StatusBadRequest)
		return false
	}

	if err := validateRequestedScope(req.Scope, client.Scopes); err != nil {
		errs.RedirectError(w, r, req.RedirectURI, errs.CodeInvalidScope, err.Error(), req.State)
		return false
	}

	return validateAuthorizePKCE(w, r, req)
}

func validateAuthorizePKCE(w http.ResponseWriter, r *http.Request, req authorizeRequest) bool {
	if req.State == "" {
		errs.RedirectError(w, r, req.RedirectURI, errs.CodeInvalidRequest, errs.MsgStateRequired, "")
		return false
	}
	if req.CodeChallenge == "" {
		errs.RedirectError(w, r, req.RedirectURI, errs.CodeInvalidRequest, errs.MsgCodeChallengeRequired, req.State)
		return false
	}
	if req.CodeChallengeMethod != "S256" {
		errs.RedirectError(w, r, req.RedirectURI, errs.CodeInvalidRequest, errs.MsgOnlyS256Allowed, req.State)
		return false
	}

	return true
}

func handleAuthorizeSubmission(w http.ResponseWriter, r *http.Request, s *store.Store, req authorizeRequest) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	user, formState, err := authorizeUserFromForm(s, r)
	if err != nil {
		renderAuthorizePage(w, req, formState)
		return
	}

	if err := redirectAuthorizedUser(w, r, s, user, req); err != nil {
		http.Error(w, "failed to issue authorization code", http.StatusInternalServerError)
	}
}

func authorizeUserFromForm(s *store.Store, r *http.Request) (*models.User, authFormState, error) {
	signupUsername := r.FormValue("signup_username")
	if signupUsername != "" {
		user := &models.User{
			Username: signupUsername,
			Email:    r.FormValue("signup_email"),
			Name:     r.FormValue("signup_name"),
			Password: r.FormValue("signup_password"),
		}
		if err := s.CreateUser(user); err != nil {
			return nil, authFormState{
				ErrorMessage:   "Username or email already taken.",
				SignupUsername: signupUsername,
				SignupEmail:    r.FormValue("signup_email"),
				SignupName:     r.FormValue("signup_name"),
			}, err
		}
		return user, authFormState{}, nil
	}

	username := r.FormValue("username")
	user, err := s.GetUserByCredentials(username, r.FormValue("password"))
	if err != nil {
		return nil, authFormState{
			ErrorMessage: "Invalid username or password.",
			Username:     username,
		}, err
	}

	return user, authFormState{}, nil
}

func redirectAuthorizedUser(w http.ResponseWriter, r *http.Request, s *store.Store, user *models.User, req authorizeRequest) error {
	code, err := generateAuthorizationCode()
	if err != nil {
		return err
	}

	s.SaveCode(&models.AuthCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              user.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})

	dest, err := authorizationRedirectURL(req.RedirectURI, code, req.State)
	if err != nil {
		return err
	}

	http.Redirect(w, r, dest, http.StatusFound)
	return nil
}

func generateAuthorizationCode() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func authorizationRedirectURL(redirectURI, code, state string) (string, error) {
	dest, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Set("code", code)
	params.Set("state", state)
	dest.RawQuery = params.Encode()
	return dest.String(), nil
}

func renderAuthorizePage(w http.ResponseWriter, req authorizeRequest, formState authFormState) {
	renderAuthPage(w, authPageData{
		Title:               "Sign in to continue",
		ErrorMessage:        formState.ErrorMessage,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Username:            formState.Username,
		SignupUsername:      formState.SignupUsername,
		SignupEmail:         formState.SignupEmail,
		SignupName:          formState.SignupName,
	})
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
		if strings.TrimSpace(a) == uri {
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
