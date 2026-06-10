package models

import (
	"database/sql"
	"database/sql/driver"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// custom-types
type StringList []string

var _ sql.Scanner = (*StringList)(nil)

func (sl *StringList) Scan(value interface{}) error {
	if value == nil {
		*sl = []string{}
		return nil
	}
	var s string
	switch v := value.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		*sl = []string{}
		return nil
	}

	if s = strings.TrimSpace(s); s == "" {
		*sl = []string{}
	} else {
		*sl = strings.Split(s, " ")
	}
	return nil
}

var _ driver.Valuer = (*StringList)(nil)

func (sl StringList) Value() (driver.Value, error) {
	if len(sl) == 0 {
		return "", nil
	}
	return strings.Join(sl, " "), nil
}

// in-map structs
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Nonce               string
	ExpiresAt           time.Time
	CodeChallenge       string // PKCE
	CodeChallengeMethod string // "S256" or "plain"
}

type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
	Nonce        string
	UserID       string
	ClientID     string
	Revoked      bool
	ExpiresAt    time.Time
}

// bun table structs
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID             string    `bun:"id,pk,unique,type:varchar(255)" json:"id"`
	Email          string    `bun:"email,unique,notnull" json:"email"`
	PasswordHash   string    `bun:"password_hash" json:"-"`
	Role           string    `bun:"role,notnull,default:'user'"`
	Audience       string    `bun:"audience,notnull,default:'mesh'"`
	EmailConfirmed bool      `bun:"email_confirmed,notnull,default:false"`
	Name           string    `bun:"name,unique" json:"username"`
	GivenName      string    `bun:"given_name" json:"name"`
	Picture        string    `bun:"picture" json:"avatar_url"`
	CreatedAt      time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt      time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp"`

	Identities []*UserIdentity `bun:"rel:has-many,join:id=user_id"`
}

type UserIdentity struct {
	bun.BaseModel `bun:"table:user_identities,alias:ui"`

	ID       string `bun:"id,pk,unique,type:varchar(255)"`
	UserID   string `bun:"user_id,notnull,type:varchar(255)"`
	Sub      string `bun:"sub,notnull,unique:sub_provider_idx"`
	Provider string `bun:"provider,notnull,unique:sub_provider_idx"`

	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp"`

	User   *User      `bun:"rel:belongs-to,join:user_id=id"`
	Tokens []*DBToken `bun:"rel:has-many,join:id=identity_id"`
}

type DBToken struct {
	bun.BaseModel `bun:"table:tokens,alias:t"`

	ID           string    `bun:"id,pk,unique,type:varchar(255)"`
	IdentityID   string    `bun:"identity_id,notnull,type:varchar(255)"`
	AccessToken  string    `bun:"access_token,notnull"`
	RefreshToken string    `bun:"refresh_token"`
	TokenType    string    `bun:"token_type"`
	ExpiresIn    int       `bun:"expires_in"`
	Scope        string    `bun:"scope"`
	Nonce        string    `bun:"nonce"`
	ClientID     string    `bun:"client_id"`
	ExpiresAt    time.Time `bun:"expires_at"`
	CreatedAt    time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp"`

	Identity *UserIdentity `bun:"rel:belongs-to,join:identity_id=id"`
}

type Client struct {
	bun.BaseModel `bun:"table:clients_info,alias:ci"`

	ID                string     `bun:"id,pk,unique,type:varchar(255)" json:"id"`
	UserID            string     `bun:"user_id,unique,notnull,type:varchar(255)" json:"user_id"`
	ClientSecret      string     `bun:"client_secret,notnull,type:varchar(255)" json:"client_secret,omitempty"`
	PublicKeyEndpoint string     `bun:"public_key,type:text" json:"public_key"`
	RedirectURIs      StringList `bun:"redirect_uris,type:text" json:"redirect_uris"` // Stored as plain text
	Scopes            StringList `bun:"scopes,type:text" json:"scopes"`

	CreatedAt time.Time `bun:"created_at,nullzero,notnull,default:current_timestamp" json:"created_at"`
	UpdatedAt time.Time `bun:"updated_at,nullzero,notnull,default:current_timestamp"`

	User *User `bun:"rel:belongs-to,join:user_id=id" json:"-"`
}
