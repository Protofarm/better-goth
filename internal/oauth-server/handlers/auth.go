package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	errs "github.com/Protofarm/better-goth/internal/oauth-server/errors"
	"github.com/Protofarm/better-goth/internal/oauth-server/keys"
	"github.com/Protofarm/better-goth/internal/oauth-server/models"
	"github.com/Protofarm/better-goth/internal/oauth-server/smtp"
	"github.com/Protofarm/better-goth/internal/oauth-server/store"
)

const OauthStateCookieName = "oauth_state"

func AuthorizeHandler(s *store.Store, devMode bool, km *keys.KeyManager, issuer string, mailer *smtp.Mailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := readAuthorizeRequest(r)
		if !validateAuthorizeRequest(w, r, s, req, devMode) {
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, errs.JSONErrMethodNotAllowed, http.StatusMethodNotAllowed)
			return
		}

		handleAuthorizeSubmission(w, r, s, req, km, issuer, mailer)
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

func handleAuthorizeSubmission(w http.ResponseWriter, r *http.Request, s *store.Store, req authorizeRequest, km *keys.KeyManager, issuer string, mailer *smtp.Mailer) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	user, formState, isNew, err := authorizeUserFromForm(s, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, formState)
		return
	}

	if isNew {
		token, err := GenerateEmailVerificationToken(user.ID, km, issuer)
		if err != nil {
			log.Printf("failed to generate verification token for user %s: %v", user.ID, err)
		} else {
			verifyURL := strings.TrimRight(issuer, "/") + "/oauth/verifyEmail?token=" + token
			if err := mailer.SendVerificationEmail(user.Email, verifyURL); err != nil {
				log.Printf("failed to send verification email to %s: %v", user.Email, err)
			}
		}
	}

	if err := redirectAuthorizedUser(w, r, s, user, req); err != nil {
		http.Error(w, "failed to issue authorization code", http.StatusInternalServerError)
	}
}

func authorizeUserFromForm(s *store.Store, r *http.Request) (*models.User, string, bool, error) {
	signupUsername := r.FormValue("signup_username")
	if signupUsername != "" {
		user := &models.User{
			Name:         signupUsername,
			Email:        r.FormValue("signup_email"),
			GivenName:    r.FormValue("signup_name"),
			PasswordHash: r.FormValue("signup_password"),
		}
		ok := validateCallbackState(r)
		if !ok {
			return nil, errs.JSONErrInvalidState, false, errors.New("invalid state")
		}
		if err := s.CreateUser(user); err != nil {
			return nil, errs.JSONErrUserAlreadyExists, false, err
		}
		return user, "", true, nil
	}

	username := r.FormValue("username")
	user, err := s.GetUserByCredentials(username, r.FormValue("password"))
	if err != nil {
		return nil, errs.JSONErrUnauthorized, false, err
	}

	return user, "", false, nil
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

func validateCallbackState(r *http.Request) bool {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(OauthStateCookieName)
	return err != nil || state != cookie.Value || state != ""
}
